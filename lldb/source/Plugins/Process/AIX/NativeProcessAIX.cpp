//===-- NativeProcessAIX.cpp --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeProcessAIX.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <unistd.h>

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include "NativeThreadAIX.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
//#include "Plugins/Process/Utility/LinuxProcMaps.h"
//#include "Procfs.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Host/Host.h"
#include "lldb/Host/HostProcess.h"
#include "lldb/Host/ProcessLaunchInfo.h"
#include "lldb/Host/PseudoTerminal.h"
#include "lldb/Host/ThreadLauncher.h"
#include "lldb/Host/common/NativeRegisterContext.h"
#include "lldb/Host/aix/Ptrace.h"
//#include "lldb/Host/linux/Host.h"
//#include "lldb/Host/linux/Uio.h"
#include "lldb/Host/posix/ProcessLauncherPosixFork.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/State.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StringExtractor.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Threading.h"

#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/ldr.h>
#include <sys/socket.h>
//#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>

#ifdef __aarch64__
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

// Support hardware breakpoints in case it has not been defined
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif

#ifndef HWCAP2_MTE
#define HWCAP2_MTE (1 << 18)
#endif

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_aix;
using namespace llvm;

// Private bits we only need internally.

static bool ProcessVmReadvSupported() {
  static bool is_supported;
  static llvm::once_flag flag;

  llvm::call_once(flag, [] {
    Log *log = GetLog(POSIXLog::Process);

    uint32_t source = 0x47424742;
    uint32_t dest = 0;

    struct iovec local, remote;
    remote.iov_base = &source;
    local.iov_base = &dest;
    remote.iov_len = local.iov_len = sizeof source;

#if 0
    // We shall try if cross-process-memory reads work by attempting to read a
    // value from our own process.
    ssize_t res = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    is_supported = (res == sizeof(source) && source == dest);
    if (is_supported)
      LLDB_LOG(log,
               "Detected kernel support for process_vm_readv syscall. "
               "Fast memory reads enabled.");
    else
      LLDB_LOG(log,
               "syscall process_vm_readv failed (error: {0}). Fast memory "
               "reads disabled.",
               llvm::sys::StrError());
#endif
  });

  return is_supported;
}

static void MaybeLogLaunchInfo(const ProcessLaunchInfo &info) {
  Log *log = GetLog(POSIXLog::Process);
  if (!log)
    return;

  if (const FileAction *action = info.GetFileActionForFD(STDIN_FILENO))
    LLDB_LOG(log, "setting STDIN to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDIN as is");

  if (const FileAction *action = info.GetFileActionForFD(STDOUT_FILENO))
    LLDB_LOG(log, "setting STDOUT to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDOUT as is");

  if (const FileAction *action = info.GetFileActionForFD(STDERR_FILENO))
    LLDB_LOG(log, "setting STDERR to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDERR as is");

  int i = 0;
  for (const char **args = info.GetArguments().GetConstArgumentVector(); *args;
       ++args, ++i)
    LLDB_LOG(log, "arg {0}: '{1}'", i, *args);
}

static void DisplayBytes(StreamString &s, void *bytes, uint32_t count) {
  uint8_t *ptr = (uint8_t *)bytes;
  const uint32_t loop_count = std::min<uint32_t>(DEBUG_PTRACE_MAXBYTES, count);
  for (uint32_t i = 0; i < loop_count; i++) {
    s.Printf("[%x]", *ptr);
    ptr++;
  }
}

static void PtraceDisplayBytes(int &req, void *data, size_t data_size) {
  Log *log = GetLog(POSIXLog::Ptrace);
  if (!log)
    return;
  StreamString buf;

  switch (req) {
  case PTRACE_POKETEXT: {
    DisplayBytes(buf, &data, 8);
    LLDB_LOGV(log, "PTRACE_POKETEXT {0}", buf.GetData());
    break;
  }
  case PTRACE_POKEDATA: {
    DisplayBytes(buf, &data, 8);
    LLDB_LOGV(log, "PTRACE_POKEDATA {0}", buf.GetData());
    break;
  }
  case PTRACE_POKEUSER: {
    DisplayBytes(buf, &data, 8);
    LLDB_LOGV(log, "PTRACE_POKEUSER {0}", buf.GetData());
    break;
  }
  case PTRACE_SETREGS: {
    DisplayBytes(buf, data, data_size);
    LLDB_LOGV(log, "PTRACE_SETREGS {0}", buf.GetData());
    break;
  }
  case PTRACE_SETFPREGS: {
    DisplayBytes(buf, data, data_size);
    LLDB_LOGV(log, "PTRACE_SETFPREGS {0}", buf.GetData());
    break;
  }
#if 0
  case PTRACE_SETSIGINFO: {
    DisplayBytes(buf, data, sizeof(siginfo_t));
    LLDB_LOGV(log, "PTRACE_SETSIGINFO {0}", buf.GetData());
    break;
  }
#endif
  case PTRACE_SETREGSET: {
    // Extract iov_base from data, which is a pointer to the struct iovec
    DisplayBytes(buf, *(void **)data, data_size);
    LLDB_LOGV(log, "PTRACE_SETREGSET {0}", buf.GetData());
    break;
  }
  default: {}
  }
}

static constexpr unsigned k_ptrace_word_size = sizeof(void *);
static_assert(sizeof(long) >= k_ptrace_word_size,
              "Size of long must be larger than ptrace word size");

// Simple helper function to ensure flags are enabled on the given file
// descriptor.
static Status EnsureFDFlags(int fd, int flags) {
  Status error;

  int status = fcntl(fd, F_GETFL);
  if (status == -1) {
    error.SetErrorToErrno();
    return error;
  }

  if (fcntl(fd, F_SETFL, status | flags) == -1) {
    error.SetErrorToErrno();
    return error;
  }

  return error;
}

// Public Static Methods

llvm::Expected<std::unique_ptr<NativeProcessProtocol>>
NativeProcessAIX::Factory::Launch(ProcessLaunchInfo &launch_info,
                                    NativeDelegate &native_delegate,
                                    MainLoop &mainloop) const {
  Log *log = GetLog(POSIXLog::Process);

  MaybeLogLaunchInfo(launch_info);

  Status status;
  ::pid_t pid = ProcessLauncherPosixFork()
                    .LaunchProcess(launch_info, status)
                    .GetProcessId();
  LLDB_LOG(log, "pid = {0:x}", pid);
  if (status.Fail()) {
    LLDB_LOG(log, "failed to launch process: {0}", status);
    return status.ToError();
  }

  // Wait for the child process to trap on its call to execve.
  int wstatus;
  ::pid_t wpid = llvm::sys::RetryAfterSignal(-1, ::waitpid, pid, &wstatus, 0);
  assert(wpid == pid);
  (void)wpid;
  if (!WIFSTOPPED(wstatus)) {
    LLDB_LOG(log, "Could not sync with inferior process: wstatus={1}",
             WaitStatus::Decode(wstatus));
    return llvm::make_error<StringError>("Could not sync with inferior process",
                                         llvm::inconvertibleErrorCode());
  }
  LLDB_LOG(log, "inferior started, now in stopped state");

  ProcessInstanceInfo Info;
  if (!Host::GetProcessInfo(pid, Info)) {
    return llvm::make_error<StringError>("Cannot get process architecture",
                                         llvm::inconvertibleErrorCode());
  }

  // Set the architecture to the exe architecture.
  LLDB_LOG(log, "pid = {0:x}, detected architecture {1}", pid,
           Info.GetArchitecture().GetArchitectureName());

  return std::unique_ptr<NativeProcessAIX>(new NativeProcessAIX(
      pid, launch_info.GetPTY().ReleasePrimaryFileDescriptor(), native_delegate,
      Info.GetArchitecture(), mainloop, {pid}));
}

llvm::Expected<std::unique_ptr<NativeProcessProtocol>>
NativeProcessAIX::Factory::Attach(
    lldb::pid_t pid, NativeProcessProtocol::NativeDelegate &native_delegate,
    MainLoop &mainloop) const {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "pid = {0:x}", pid);

  // Retrieve the architecture for the running process.
  ProcessInstanceInfo Info;
  if (!Host::GetProcessInfo(pid, Info)) {
    return llvm::make_error<StringError>("Cannot get process architecture",
                                         llvm::inconvertibleErrorCode());
  }

  auto tids_or = NativeProcessAIX::Attach(pid);
  if (!tids_or)
    return tids_or.takeError();

  return std::unique_ptr<NativeProcessAIX>(new NativeProcessAIX(
      pid, -1, native_delegate, Info.GetArchitecture(), mainloop, *tids_or));
}

lldb::addr_t NativeProcessAIX::GetSharedLibraryInfoAddress() {
  // punt on this for now
  return LLDB_INVALID_ADDRESS;
}

NativeProcessAIX::Extension
NativeProcessAIX::Factory::GetSupportedExtensions() const {
  NativeProcessAIX::Extension supported =
      Extension::multiprocess | Extension::fork | Extension::vfork |
      Extension::pass_signals | Extension::auxv | Extension::libraries_svr4 |
      Extension::siginfo_read;

#ifdef __aarch64__
  // At this point we do not have a process so read auxv directly.
  if ((getauxval(AT_HWCAP2) & HWCAP2_MTE))
    supported |= Extension::memory_tagging;
#endif

  return supported;
}

// Public Instance Methods

NativeProcessAIX::NativeProcessAIX(::pid_t pid, int terminal_fd,
                                       NativeDelegate &delegate,
                                       const ArchSpec &arch, MainLoop &mainloop,
                                       llvm::ArrayRef<::pid_t> tids)
    : NativeProcessProtocol(pid, terminal_fd, delegate), m_arch(arch),
      m_main_loop(mainloop) {
  if (m_terminal_fd != -1) {
    Status status = EnsureFDFlags(m_terminal_fd, O_NONBLOCK);
    assert(status.Success());
  }

  Status status;
  m_sigchld_handle = mainloop.RegisterSignal(
      SIGCHLD, [this](MainLoopBase &) { SigchldHandler(); }, status);
  assert(m_sigchld_handle && status.Success());

  for (const auto &tid : tids) {
    NativeThreadAIX &thread = AddThread(tid, /*resume*/ false);
    ThreadWasCreated(thread);
  }

  // Let our process instance know the thread has stopped.
  SetCurrentThreadID(tids[0]);
  SetState(StateType::eStateStopped, false);

  // Proccess any signals we received before installing our handler
  SigchldHandler();
}

llvm::Expected<std::vector<::pid_t>> NativeProcessAIX::Attach(::pid_t pid) {
  Log *log = GetLog(POSIXLog::Process);

  Status status;
  if ((status = PtraceWrapper(PT_ATTACH, pid)).Fail()) {
    return status.ToError();
  }

  int wpid =
      llvm::sys::RetryAfterSignal(-1, ::waitpid, pid, nullptr, WNOHANG);
  if (wpid <= 0) {
    return llvm::errorCodeToError(
        std::error_code(errno, std::generic_category()));
  }

  LLDB_LOG(log, "adding pid = {0}", pid);

  std::vector<::pid_t> tids;
  tids.push_back(pid);
  return std::move(tids);
}

// Handles all waitpid events from the inferior process.
void NativeProcessAIX::MonitorCallback(NativeThreadAIX &thread,
                                         WaitStatus status) {
  Log *log = GetLog(LLDBLog::Process);

  // Certain activities differ based on whether the pid is the tid of the main
  // thread.
  const bool is_main_thread = (thread.GetID() == GetID());

  // Handle when the thread exits.
  if (status.type == WaitStatus::Exit || status.type == WaitStatus::Signal) {
    LLDB_LOG(log,
             "got exit status({0}) , tid = {1} ({2} main thread), process "
             "state = {3}",
             status, thread.GetID(), is_main_thread ? "is" : "is not",
             GetState());

    // This is a thread that exited.  Ensure we're not tracking it anymore.
    StopTrackingThread(thread);

    assert(!is_main_thread && "Main thread exits handled elsewhere");
    return;
  }

  int8_t signo = GetSignalInfo(status);

  // Get details on the signal raised.
  if (signo) {
    // We have retrieved the signal info.  Dispatch appropriately.
    if (signo == SIGTRAP)
      MonitorSIGTRAP(status, thread);
    else
      MonitorSignal(status, thread);
  } else {
    assert(0);
  }
}

void NativeProcessAIX::WaitForCloneNotification(::pid_t pid) {
  Log *log = GetLog(POSIXLog::Process);

  // The PID is not tracked yet, let's wait for it to appear.
  int status = -1;
  LLDB_LOG(log,
           "received clone event for pid {0}. pid not tracked yet, "
           "waiting for it to appear...",
           pid);
  //FIXME
  ::pid_t wait_pid =
      llvm::sys::RetryAfterSignal(-1, ::waitpid, pid, &status, P_ALL/*__WALL*/);

  // It's theoretically possible to get other events if the entire process was
  // SIGKILLed before we got a chance to check this. In that case, we'll just
  // clean everything up when we get the process exit event.

  //FIXME
  LLDB_LOG(log,
           "waitpid({0}, &status, P_ALL/*__WALL*/) => {1} (errno: {2}, status = {3})",
           pid, wait_pid, errno, WaitStatus::Decode(status));
}

void NativeProcessAIX::MonitorSIGTRAP(const WaitStatus status,
                                        NativeThreadAIX &thread) {
  Log *log = GetLog(POSIXLog::Process);
  const bool is_main_thread = (thread.GetID() == GetID());

  switch (status.status) {
  case SIGTRAP:
    MonitorBreakpoint(thread);
    break;
  default:
    LLDB_LOG(log, "received unknown SIGTRAP stop event ({0}, pid {1} tid {2}",
             status.status, GetID(), thread.GetID());
    MonitorSignal(status, thread);
    break;
  }
}

void NativeProcessAIX::MonitorTrace(NativeThreadAIX &thread) {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "received trace event, pid = {0}", thread.GetID());

  // This thread is currently stopped.
  thread.SetStoppedByTrace();

  StopRunningThreads(thread.GetID());
}

void NativeProcessAIX::MonitorBreakpoint(NativeThreadAIX &thread) {
  Log *log = GetLog(LLDBLog::Process | LLDBLog::Breakpoints);
  LLDB_LOG(log, "received breakpoint event, pid = {0}", thread.GetID());

  // Mark the thread as stopped at breakpoint.
  thread.SetStoppedByBreakpoint();
  FixupBreakpointPCAsNeeded(thread);

  if (m_threads_stepping_with_breakpoint.find(thread.GetID()) !=
      m_threads_stepping_with_breakpoint.end())
    thread.SetStoppedByTrace();

  StopRunningThreads(thread.GetID());
}

void NativeProcessAIX::MonitorWatchpoint(NativeThreadAIX &thread,
                                           uint32_t wp_index) {
  Log *log = GetLog(LLDBLog::Process | LLDBLog::Watchpoints);
  LLDB_LOG(log, "received watchpoint event, pid = {0}, wp_index = {1}",
           thread.GetID(), wp_index);

  // Mark the thread as stopped at watchpoint. The address is at
  // (lldb::addr_t)info->si_addr if we need it.
  thread.SetStoppedByWatchpoint(wp_index);

  // We need to tell all other running threads before we notify the delegate
  // about this stop.
  StopRunningThreads(thread.GetID());
}

void NativeProcessAIX::MonitorSignal(const WaitStatus status,
                                       NativeThreadAIX &thread) {
#if 0
  const int signo = info.si_signo;
  const bool is_from_llgs = info.si_pid == getpid();

  Log *log = GetLog(POSIXLog::Process);

  // POSIX says that process behaviour is undefined after it ignores a SIGFPE,
  // SIGILL, SIGSEGV, or SIGBUS *unless* that signal was generated by a kill(2)
  // or raise(3).  Similarly for tgkill(2) on AIX.
  //
  // IOW, user generated signals never generate what we consider to be a
  // "crash".
  //
  // Similarly, ACK signals generated by this monitor.

  // Handle the signal.
  LLDB_LOG(log,
           "received signal {0} ({1}) with code {2}, (siginfo pid = {3}, "
           "waitpid pid = {4})",
           Host::GetSignalAsCString(signo), signo, info.si_code,
           thread.GetID());

  // Check for thread stop notification.
  // FIXME
  if (is_from_llgs /*&& (info.si_code == SI_TKILL)*/ && (signo == SIGSTOP)) {
    // This is a tgkill()-based stop.
    LLDB_LOG(log, "pid {0} tid {1}, thread stopped", GetID(), thread.GetID());

    // Check that we're not already marked with a stop reason. Note this thread
    // really shouldn't already be marked as stopped - if we were, that would
    // imply that the kernel signaled us with the thread stopping which we
    // handled and marked as stopped, and that, without an intervening resume,
    // we received another stop.  It is more likely that we are missing the
    // marking of a run state somewhere if we find that the thread was marked
    // as stopped.
    const StateType thread_state = thread.GetState();
    if (!StateIsStoppedState(thread_state, false)) {
      // An inferior thread has stopped because of a SIGSTOP we have sent it.
      // Generally, these are not important stops and we don't want to report
      // them as they are just used to stop other threads when one thread (the
      // one with the *real* stop reason) hits a breakpoint (watchpoint,
      // etc...). However, in the case of an asynchronous Interrupt(), this
      // *is* the real stop reason, so we leave the signal intact if this is
      // the thread that was chosen as the triggering thread.
      if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID) {
        if (m_pending_notification_tid == thread.GetID())
          thread.SetStoppedBySignal(SIGSTOP, &info);
        else
          thread.SetStoppedWithNoReason();

        SetCurrentThreadID(thread.GetID());
        SignalIfAllThreadsStopped();
      } else {
        // We can end up here if stop was initiated by LLGS but by this time a
        // thread stop has occurred - maybe initiated by another event.
        Status error = ResumeThread(thread, thread.GetState(), 0);
        if (error.Fail())
          LLDB_LOG(log, "failed to resume thread {0}: {1}", thread.GetID(),
                   error);
      }
    } else {
      LLDB_LOG(log,
               "pid {0} tid {1}, thread was already marked as a stopped "
               "state (state={2}), leaving stop signal as is",
               GetID(), thread.GetID(), thread_state);
      SignalIfAllThreadsStopped();
    }

    // Done handling.
    return;
  }

  // Check if debugger should stop at this signal or just ignore it and resume
  // the inferior.
  if (m_signals_to_ignore.contains(signo)) {
     ResumeThread(thread, thread.GetState(), signo);
     return;
  }

  // This thread is stopped.
  LLDB_LOG(log, "received signal {0}", Host::GetSignalAsCString(signo));
  thread.SetStoppedBySignal(signo, &info);

  // Send a stop to the debugger after we get all other threads to stop.
  StopRunningThreads(thread.GetID());
#endif
}

bool NativeProcessAIX::MonitorClone(NativeThreadAIX &parent,
                                      lldb::pid_t child_pid, int event) {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "parent_tid={0}, child_pid={1}, event={2}", parent.GetID(),
           child_pid, event);

  WaitForCloneNotification(child_pid);

  switch (event) {
#if 0
  case PTRACE_EVENT_CLONE: {
    // PTRACE_EVENT_CLONE can either mean a new thread or a new process.
    // Try to grab the new process' PGID to figure out which one it is.
    // If PGID is the same as the PID, then it's a new process.  Otherwise,
    // it's a thread.
    auto tgid_ret = getPIDForTID(child_pid);
    if (tgid_ret != child_pid) {
      // A new thread should have PGID matching our process' PID.
      assert(!tgid_ret || tgid_ret.getValue() == GetID());

      NativeThreadAIX &child_thread = AddThread(child_pid, /*resume*/ true);
      ThreadWasCreated(child_thread);

      // Resume the parent.
      ResumeThread(parent, parent.GetState(), LLDB_INVALID_SIGNAL_NUMBER);
      break;
    }
  }
    LLVM_FALLTHROUGH;
  case PTRACE_EVENT_FORK:
  case PTRACE_EVENT_VFORK: {
    bool is_vfork = event == PTRACE_EVENT_VFORK;
    std::unique_ptr<NativeProcessAIX> child_process{new NativeProcessAIX(
        static_cast<::pid_t>(child_pid), m_terminal_fd, m_delegate, m_arch,
        m_main_loop, {static_cast<::pid_t>(child_pid)})};
    if (!is_vfork)
      child_process->m_software_breakpoints = m_software_breakpoints;

    Extension expected_ext = is_vfork ? Extension::vfork : Extension::fork;
    if (bool(m_enabled_extensions & expected_ext)) {
      m_delegate.NewSubprocess(this, std::move(child_process));
      // NB: non-vfork clone() is reported as fork
      parent.SetStoppedByFork(is_vfork, child_pid);
      StopRunningThreads(parent.GetID());
    } else {
      child_process->Detach();
      ResumeThread(parent, parent.GetState(), LLDB_INVALID_SIGNAL_NUMBER);
    }
    break;
  }
#endif
  default:
    llvm_unreachable("unknown clone_info.event");
  }

  return true;
}

bool NativeProcessAIX::SupportHardwareSingleStepping() const {
  if (m_arch.GetMachine() == llvm::Triple::arm || m_arch.IsMIPS())
    return false;
  return true;
}

Status NativeProcessAIX::Resume(const ResumeActionList &resume_actions) {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "pid {0}", GetID());

  bool software_single_step = !SupportHardwareSingleStepping();

  if (software_single_step) {
    for (const auto &thread : m_threads) {
      assert(thread && "thread list should not contain NULL threads");

      const ResumeAction *const action =
          resume_actions.GetActionForThread(thread->GetID(), true);
      if (action == nullptr)
        continue;

      if (action->state == eStateStepping) {
        Status error = SetupSoftwareSingleStepping(
            static_cast<NativeThreadAIX &>(*thread));
        if (error.Fail())
          return error;
      }
    }
  }

  for (const auto &thread : m_threads) {
    assert(thread && "thread list should not contain NULL threads");

    const ResumeAction *const action =
        resume_actions.GetActionForThread(thread->GetID(), true);

    if (action == nullptr) {
      LLDB_LOG(log, "no action specified for pid {0} tid {1}", GetID(),
               thread->GetID());
      continue;
    }

    LLDB_LOG(log, "processing resume action state {0} for pid {1} tid {2}",
             action->state, GetID(), thread->GetID());

    switch (action->state) {
    case eStateRunning:
    case eStateStepping: {
      // Run the thread, possibly feeding it the signal.
      const int signo = action->signal;
      ResumeThread(static_cast<NativeThreadAIX &>(*thread), action->state,
                   signo);
      break;
    }

    case eStateSuspended:
    case eStateStopped:
      llvm_unreachable("Unexpected state");

    default:
      return Status("NativeProcessAIX::%s (): unexpected state %s specified "
                    "for pid %" PRIu64 ", tid %" PRIu64,
                    __FUNCTION__, StateAsCString(action->state), GetID(),
                    thread->GetID());
    }
  }

  return Status();
}

Status NativeProcessAIX::Halt() {
  Status error;

  if (kill(GetID(), SIGSTOP) != 0)
    error.SetErrorToErrno();

  return error;
}

Status NativeProcessAIX::Detach() {
  Status error;

  // Stop monitoring the inferior.
  m_sigchld_handle.reset();

  // Tell ptrace to detach from the process.
  if (GetID() == LLDB_INVALID_PROCESS_ID)
    return error;

  for (const auto &thread : m_threads) {
    Status e = Detach(thread->GetID());
    if (e.Fail())
      error =
          e; // Save the error, but still attempt to detach from other threads.
  }

  return error;
}

Status NativeProcessAIX::Signal(int signo) {
  Status error;

  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "sending signal {0} ({1}) to pid {1}", signo,
           Host::GetSignalAsCString(signo), GetID());

  if (kill(GetID(), signo))
    error.SetErrorToErrno();

  return error;
}

Status NativeProcessAIX::Interrupt() {
  // Pick a running thread (or if none, a not-dead stopped thread) as the
  // chosen thread that will be the stop-reason thread.
  Log *log = GetLog(POSIXLog::Process);

  NativeThreadProtocol *running_thread = nullptr;
  NativeThreadProtocol *stopped_thread = nullptr;

  LLDB_LOG(log, "selecting running thread for interrupt target");
  for (const auto &thread : m_threads) {
    // If we have a running or stepping thread, we'll call that the target of
    // the interrupt.
    const auto thread_state = thread->GetState();
    if (thread_state == eStateRunning || thread_state == eStateStepping) {
      running_thread = thread.get();
      break;
    } else if (!stopped_thread && StateIsStoppedState(thread_state, true)) {
      // Remember the first non-dead stopped thread.  We'll use that as a
      // backup if there are no running threads.
      stopped_thread = thread.get();
    }
  }

  if (!running_thread && !stopped_thread) {
    Status error("found no running/stepping or live stopped threads as target "
                 "for interrupt");
    LLDB_LOG(log, "skipping due to error: {0}", error);

    return error;
  }

  NativeThreadProtocol *deferred_signal_thread =
      running_thread ? running_thread : stopped_thread;

  LLDB_LOG(log, "pid {0} {1} tid {2} chosen for interrupt target", GetID(),
           running_thread ? "running" : "stopped",
           deferred_signal_thread->GetID());

  StopRunningThreads(deferred_signal_thread->GetID());

  return Status();
}

Status NativeProcessAIX::Kill() {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "pid {0}", GetID());

  Status error;

  switch (m_state) {
  case StateType::eStateInvalid:
  case StateType::eStateExited:
  case StateType::eStateCrashed:
  case StateType::eStateDetached:
  case StateType::eStateUnloaded:
    // Nothing to do - the process is already dead.
    LLDB_LOG(log, "ignored for PID {0} due to current state: {1}", GetID(),
             m_state);
    return error;

  case StateType::eStateConnected:
  case StateType::eStateAttaching:
  case StateType::eStateLaunching:
  case StateType::eStateStopped:
  case StateType::eStateRunning:
  case StateType::eStateStepping:
  case StateType::eStateSuspended:
    // We can try to kill a process in these states.
    break;
  }

  if (kill(GetID(), SIGKILL) != 0) {
    error.SetErrorToErrno();
    return error;
  }

  return error;
}

Status NativeProcessAIX::GetMemoryRegionInfo(lldb::addr_t load_addr,
                                               MemoryRegionInfo &range_info) {
  // FIXME review that the final memory region returned extends to the end of
  // the virtual address space,
  // with no perms if it is not mapped.

  // Use an approach that reads memory regions from /proc/{pid}/maps. Assume
  // proc maps entries are in ascending order.
  // FIXME assert if we find differently.

  if (m_supports_mem_region == LazyBool::eLazyBoolNo) {
    // We're done.
    return Status("unsupported");
  }

  Status error = PopulateMemoryRegionCache();
  if (error.Fail()) {
    return error;
  }

  lldb::addr_t prev_base_address = 0;

  // FIXME start by finding the last region that is <= target address using
  // binary search.  Data is sorted.
  // There can be a ton of regions on pthreads apps with lots of threads.
  for (auto it = m_mem_region_cache.begin(); it != m_mem_region_cache.end();
       ++it) {
    MemoryRegionInfo &proc_entry_info = it->first;

    // Sanity check assumption that /proc/{pid}/maps entries are ascending.
    assert((proc_entry_info.GetRange().GetRangeBase() >= prev_base_address) &&
           "descending /proc/pid/maps entries detected, unexpected");
    prev_base_address = proc_entry_info.GetRange().GetRangeBase();
    UNUSED_IF_ASSERT_DISABLED(prev_base_address);

    // If the target address comes before this entry, indicate distance to next
    // region.
    if (load_addr < proc_entry_info.GetRange().GetRangeBase()) {
      range_info.GetRange().SetRangeBase(load_addr);
      range_info.GetRange().SetByteSize(
          proc_entry_info.GetRange().GetRangeBase() - load_addr);
      range_info.SetReadable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetWritable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetExecutable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetMapped(MemoryRegionInfo::OptionalBool::eNo);

      return error;
    } else if (proc_entry_info.GetRange().Contains(load_addr)) {
      // The target address is within the memory region we're processing here.
      range_info = proc_entry_info;
      return error;
    }

    // The target memory address comes somewhere after the region we just
    // parsed.
  }

  // If we made it here, we didn't find an entry that contained the given
  // address. Return the load_addr as start and the amount of bytes betwwen
  // load address and the end of the memory as size.
  range_info.GetRange().SetRangeBase(load_addr);
  range_info.GetRange().SetRangeEnd(LLDB_INVALID_ADDRESS);
  range_info.SetReadable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetWritable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetExecutable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetMapped(MemoryRegionInfo::OptionalBool::eNo);
  return error;
}

Status NativeProcessAIX::PopulateMemoryRegionCache() {
  Log *log = GetLog(POSIXLog::Process);

  // If our cache is empty, pull the latest.  There should always be at least
  // one memory region if memory region handling is supported.
  if (!m_mem_region_cache.empty()) {
    LLDB_LOG(log, "reusing {0} cached memory region entries",
             m_mem_region_cache.size());
    return Status();
  }

  Status Result;
#if 0
  AIXMapCallback callback = [&](llvm::Expected<MemoryRegionInfo> Info) {
    if (Info) {
      FileSpec file_spec(Info->GetName().GetCString());
      FileSystem::Instance().Resolve(file_spec);
      m_mem_region_cache.emplace_back(*Info, file_spec);
      return true;
    }

    Result = Info.takeError();
    m_supports_mem_region = LazyBool::eLazyBoolNo;
    LLDB_LOG(log, "failed to parse proc maps: {0}", Result);
    return false;
  };

  // AIX kernel since 2.6.14 has /proc/{pid}/smaps
  // if CONFIG_PROC_PAGE_MONITOR is enabled
  auto BufferOrError = getProcFile(GetID(), GetCurrentThreadID(), "smaps");
  if (BufferOrError)
    ParseAIXSMapRegions(BufferOrError.get()->getBuffer(), callback);
  else {
    BufferOrError = getProcFile(GetID(), GetCurrentThreadID(), "maps");
    if (!BufferOrError) {
      m_supports_mem_region = LazyBool::eLazyBoolNo;
      return BufferOrError.getError();
    }

    ParseAIXMapRegions(BufferOrError.get()->getBuffer(), callback);
  }

  if (Result.Fail())
    return Result;

  if (m_mem_region_cache.empty()) {
    // No entries after attempting to read them.  This shouldn't happen if
    // /proc/{pid}/maps is supported. Assume we don't support map entries via
    // procfs.
    m_supports_mem_region = LazyBool::eLazyBoolNo;
    LLDB_LOG(log,
             "failed to find any procfs maps entries, assuming no support "
             "for memory region metadata retrieval");
    return Status("not supported");
  }

  LLDB_LOG(log, "read {0} memory region entries from /proc/{1}/maps",
           m_mem_region_cache.size(), GetID());

  // We support memory retrieval, remember that.
  m_supports_mem_region = LazyBool::eLazyBoolYes;
#endif
  return Status();
}

void NativeProcessAIX::DoStopIDBumped(uint32_t newBumpId) {
  Log *log = GetLog(POSIXLog::Process);
  LLDB_LOG(log, "newBumpId={0}", newBumpId);
  LLDB_LOG(log, "clearing {0} entries from memory region cache",
           m_mem_region_cache.size());
  m_mem_region_cache.clear();
}

llvm::Expected<uint64_t>
NativeProcessAIX::Syscall(llvm::ArrayRef<uint64_t> args) {
  PopulateMemoryRegionCache();
  auto region_it = llvm::find_if(m_mem_region_cache, [](const auto &pair) {
    return pair.first.GetExecutable() == MemoryRegionInfo::eYes;
  });
  if (region_it == m_mem_region_cache.end())
    return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                   "No executable memory region found!");

  addr_t exe_addr = region_it->first.GetRange().GetRangeBase();

  NativeThreadAIX &thread = *GetCurrentThread();
  assert(thread.GetState() == eStateStopped);
  NativeRegisterContextAIX &reg_ctx = thread.GetRegisterContext();

  NativeRegisterContextAIX::SyscallData syscall_data =
      *reg_ctx.GetSyscallData();

  WritableDataBufferSP registers_sp;
  if (llvm::Error Err = reg_ctx.ReadAllRegisterValues(registers_sp).ToError())
    return std::move(Err);
  auto restore_regs = llvm::make_scope_exit(
      [&] { reg_ctx.WriteAllRegisterValues(registers_sp); });

  llvm::SmallVector<uint8_t, 8> memory(syscall_data.Insn.size());
  size_t bytes_read;
  if (llvm::Error Err =
          ReadMemory(exe_addr, memory.data(), memory.size(), bytes_read)
              .ToError()) {
    return std::move(Err);
  }

  auto restore_mem = llvm::make_scope_exit(
      [&] { WriteMemory(exe_addr, memory.data(), memory.size(), bytes_read); });

  if (llvm::Error Err = reg_ctx.SetPC(exe_addr).ToError())
    return std::move(Err);

  for (const auto &zip : llvm::zip_first(args, syscall_data.Args)) {
    if (llvm::Error Err =
            reg_ctx
                .WriteRegisterFromUnsigned(std::get<1>(zip), std::get<0>(zip))
                .ToError()) {
      return std::move(Err);
    }
  }
  if (llvm::Error Err = WriteMemory(exe_addr, syscall_data.Insn.data(),
                                    syscall_data.Insn.size(), bytes_read)
                            .ToError())
    return std::move(Err);

  m_mem_region_cache.clear();

  // With software single stepping the syscall insn buffer must also include a
  // trap instruction to stop the process.
  int req = SupportHardwareSingleStepping() ? PTRACE_SINGLESTEP : PTRACE_CONT;
  if (llvm::Error Err =
          PtraceWrapper(req, thread.GetID(), nullptr, nullptr).ToError())
    return std::move(Err);

  //FIXME
  int status;
  ::pid_t wait_pid = llvm::sys::RetryAfterSignal(-1, ::waitpid, thread.GetID(),
                                                 &status, P_ALL/*__WALL*/);
  if (wait_pid == -1) {
    return llvm::errorCodeToError(
        std::error_code(errno, std::generic_category()));
  }
  assert((unsigned)wait_pid == thread.GetID());

  uint64_t result = reg_ctx.ReadRegisterAsUnsigned(syscall_data.Result, -ESRCH);

  // Values larger than this are actually negative errno numbers.
  uint64_t errno_threshold =
      (uint64_t(-1) >> (64 - 8 * m_arch.GetAddressByteSize())) - 0x1000;
  if (result > errno_threshold) {
    return llvm::errorCodeToError(
        std::error_code(-result & 0xfff, std::generic_category()));
  }

  return result;
}

llvm::Expected<addr_t>
NativeProcessAIX::AllocateMemory(size_t size, uint32_t permissions) {

  llvm::Optional<NativeRegisterContextAIX::MmapData> mmap_data =
      GetCurrentThread()->GetRegisterContext().GetMmapData();
  if (!mmap_data)
    return llvm::make_error<UnimplementedError>();

  unsigned prot = PROT_NONE;
  assert((permissions & (ePermissionsReadable | ePermissionsWritable |
                         ePermissionsExecutable)) == permissions &&
         "Unknown permission!");
  if (permissions & ePermissionsReadable)
    prot |= PROT_READ;
  if (permissions & ePermissionsWritable)
    prot |= PROT_WRITE;
  if (permissions & ePermissionsExecutable)
    prot |= PROT_EXEC;

  llvm::Expected<uint64_t> Result =
      Syscall({mmap_data->SysMmap, 0, size, prot, MAP_ANONYMOUS | MAP_PRIVATE,
               uint64_t(-1), 0});
  if (Result)
    m_allocated_memory.try_emplace(*Result, size);
  return Result;
}

llvm::Error NativeProcessAIX::DeallocateMemory(lldb::addr_t addr) {
  llvm::Optional<NativeRegisterContextAIX::MmapData> mmap_data =
      GetCurrentThread()->GetRegisterContext().GetMmapData();
  if (!mmap_data)
    return llvm::make_error<UnimplementedError>();

  auto it = m_allocated_memory.find(addr);
  if (it == m_allocated_memory.end())
    return llvm::createStringError(llvm::errc::invalid_argument,
                                   "Memory not allocated by the debugger.");

  llvm::Expected<uint64_t> Result =
      Syscall({mmap_data->SysMunmap, addr, it->second});
  if (!Result)
    return Result.takeError();

  m_allocated_memory.erase(it);
  return llvm::Error::success();
}

Status NativeProcessAIX::ReadMemoryTags(int32_t type, lldb::addr_t addr,
                                          size_t len,
                                          std::vector<uint8_t> &tags) {
  llvm::Expected<NativeRegisterContextAIX::MemoryTaggingDetails> details =
      GetCurrentThread()->GetRegisterContext().GetMemoryTaggingDetails(type);
  if (!details)
    return Status(details.takeError());

  // Ignore 0 length read
  if (!len)
    return Status();

  // lldb will align the range it requests but it is not required to by
  // the protocol so we'll do it again just in case.
  // Remove tag bits too. Ptrace calls may work regardless but that
  // is not a guarantee.
  MemoryTagManager::TagRange range(details->manager->RemoveTagBits(addr), len);
  range = details->manager->ExpandToGranule(range);

  // Allocate enough space for all tags to be read
  size_t num_tags = range.GetByteSize() / details->manager->GetGranuleSize();
  tags.resize(num_tags * details->manager->GetTagSizeInBytes());

  struct iovec tags_iovec;
  uint8_t *dest = tags.data();
  lldb::addr_t read_addr = range.GetRangeBase();

  // This call can return partial data so loop until we error or
  // get all tags back.
  while (num_tags) {
    tags_iovec.iov_base = dest;
    tags_iovec.iov_len = num_tags;

    Status error = NativeProcessAIX::PtraceWrapper(
        details->ptrace_read_req, GetCurrentThreadID(),
        reinterpret_cast<void *>(read_addr), static_cast<void *>(&tags_iovec),
        0, nullptr);

    if (error.Fail()) {
      // Discard partial reads
      tags.resize(0);
      return error;
    }

    size_t tags_read = tags_iovec.iov_len;
    assert(tags_read && (tags_read <= num_tags));

    dest += tags_read * details->manager->GetTagSizeInBytes();
    read_addr += details->manager->GetGranuleSize() * tags_read;
    num_tags -= tags_read;
  }

  return Status();
}

Status NativeProcessAIX::WriteMemoryTags(int32_t type, lldb::addr_t addr,
                                           size_t len,
                                           const std::vector<uint8_t> &tags) {
  llvm::Expected<NativeRegisterContextAIX::MemoryTaggingDetails> details =
      GetCurrentThread()->GetRegisterContext().GetMemoryTaggingDetails(type);
  if (!details)
    return Status(details.takeError());

  // Ignore 0 length write
  if (!len)
    return Status();

  // lldb will align the range it requests but it is not required to by
  // the protocol so we'll do it again just in case.
  // Remove tag bits too. Ptrace calls may work regardless but that
  // is not a guarantee.
  MemoryTagManager::TagRange range(details->manager->RemoveTagBits(addr), len);
  range = details->manager->ExpandToGranule(range);

  // Not checking number of tags here, we may repeat them below
  llvm::Expected<std::vector<lldb::addr_t>> unpacked_tags_or_err =
      details->manager->UnpackTagsData(tags);
  if (!unpacked_tags_or_err)
    return Status(unpacked_tags_or_err.takeError());

  llvm::Expected<std::vector<lldb::addr_t>> repeated_tags_or_err =
      details->manager->RepeatTagsForRange(*unpacked_tags_or_err, range);
  if (!repeated_tags_or_err)
    return Status(repeated_tags_or_err.takeError());

  // Repack them for ptrace to use
  llvm::Expected<std::vector<uint8_t>> final_tag_data =
      details->manager->PackTags(*repeated_tags_or_err);
  if (!final_tag_data)
    return Status(final_tag_data.takeError());

  struct iovec tags_vec;
  uint8_t *src = final_tag_data->data();
  lldb::addr_t write_addr = range.GetRangeBase();
  // unpacked tags size because the number of bytes per tag might not be 1
  size_t num_tags = repeated_tags_or_err->size();

  // This call can partially write tags, so we loop until we
  // error or all tags have been written.
  while (num_tags > 0) {
    tags_vec.iov_base = src;
    tags_vec.iov_len = num_tags;

    Status error = NativeProcessAIX::PtraceWrapper(
        details->ptrace_write_req, GetCurrentThreadID(),
        reinterpret_cast<void *>(write_addr), static_cast<void *>(&tags_vec), 0,
        nullptr);

    if (error.Fail()) {
      // Don't attempt to restore the original values in the case of a partial
      // write
      return error;
    }

    size_t tags_written = tags_vec.iov_len;
    assert(tags_written && (tags_written <= num_tags));

    src += tags_written * details->manager->GetTagSizeInBytes();
    write_addr += details->manager->GetGranuleSize() * tags_written;
    num_tags -= tags_written;
  }

  return Status();
}

size_t NativeProcessAIX::UpdateThreads() {
  // The NativeProcessAIX monitoring threads are always up to date with
  // respect to thread state and they keep the thread list populated properly.
  // All this method needs to do is return the thread count.
  return m_threads.size();
}

Status NativeProcessAIX::SetBreakpoint(lldb::addr_t addr, uint32_t size,
                                         bool hardware) {
  if (hardware)
    return SetHardwareBreakpoint(addr, size);
  else
    return SetSoftwareBreakpoint(addr, size);
}

Status NativeProcessAIX::RemoveBreakpoint(lldb::addr_t addr, bool hardware) {
  if (hardware)
    return RemoveHardwareBreakpoint(addr);
  else
    return NativeProcessProtocol::RemoveBreakpoint(addr);
}

llvm::Expected<llvm::ArrayRef<uint8_t>>
NativeProcessAIX::GetSoftwareBreakpointTrapOpcode(size_t size_hint) {
  // The ARM reference recommends the use of 0xe7fddefe and 0xdefe but the
  // linux kernel does otherwise.
  static const uint8_t g_arm_opcode[] = {0xf0, 0x01, 0xf0, 0xe7};
  static const uint8_t g_thumb_opcode[] = {0x01, 0xde};

  switch (GetArchitecture().GetMachine()) {
  case llvm::Triple::arm:
    switch (size_hint) {
    case 2:
      return llvm::makeArrayRef(g_thumb_opcode);
    case 4:
      return llvm::makeArrayRef(g_arm_opcode);
    default:
      return llvm::createStringError(llvm::inconvertibleErrorCode(),
                                     "Unrecognised trap opcode size hint!");
    }
  default:
    return NativeProcessProtocol::GetSoftwareBreakpointTrapOpcode(size_hint);
  }
}

Status NativeProcessAIX::ReadMemory(lldb::addr_t addr, void *buf, size_t size,
                                      size_t &bytes_read) {
  unsigned char *dst = static_cast<unsigned char *>(buf);
  size_t remainder;
  long data;

  Log *log = GetLog(POSIXLog::Memory);
  LLDB_LOG(log, "addr = {0}, buf = {1}, size = {2}", addr, buf, size);

  for (bytes_read = 0; bytes_read < size; bytes_read += remainder) {
    Status error = NativeProcessAIX::PtraceWrapper(
        PT_READ_BLOCK, GetCurrentThreadID(), (void *)addr, nullptr, sizeof(data), &data);
    if (error.Fail())
      return error;

    remainder = size - bytes_read;
    remainder = remainder > k_ptrace_word_size ? k_ptrace_word_size : remainder;

    // Copy the data into our buffer
    memcpy(dst, &data, remainder);

    LLDB_LOG(log, "[{0:x}]:{1:x}", addr, data);
    addr += k_ptrace_word_size;
    dst += k_ptrace_word_size;
  }
  return Status();
}

Status NativeProcessAIX::WriteMemory(lldb::addr_t addr, const void *buf,
                                       size_t size, size_t &bytes_written) {
  const unsigned char *src = static_cast<const unsigned char *>(buf);
  size_t remainder;
  Status error;

  Log *log = GetLog(POSIXLog::Memory);
  LLDB_LOG(log, "addr = {0}, buf = {1}, size = {2}", addr, buf, size);

  error = NativeProcessAIX::PtraceWrapper(
    PT_WRITE_BLOCK, GetCurrentThreadID(), (void *)addr, nullptr, (int)size, (long *)buf);
  if (error.Fail())
    return error;

  bytes_written = size;
  return error;
}

int8_t NativeProcessAIX::GetSignalInfo(WaitStatus wstatus) const {
  return wstatus.status;
}

Status NativeProcessAIX::GetEventMessage(lldb::tid_t tid,
                                           unsigned long *message) {
  //FIXME
  return PtraceWrapper(PT_CLEAR/*PTRACE_GETEVENTMSG*/, tid, nullptr, message);
}

Status NativeProcessAIX::Detach(lldb::tid_t tid) {
  if (tid == LLDB_INVALID_THREAD_ID)
    return Status();

  return PtraceWrapper(PT_DETACH, tid);
}

bool NativeProcessAIX::HasThreadNoLock(lldb::tid_t thread_id) {
  for (const auto &thread : m_threads) {
    assert(thread && "thread list should not contain NULL threads");
    if (thread->GetID() == thread_id) {
      // We have this thread.
      return true;
    }
  }

  // We don't have this thread.
  return false;
}

void NativeProcessAIX::StopTrackingThread(NativeThreadAIX &thread) {
  Log *const log = GetLog(POSIXLog::Thread);
  lldb::tid_t thread_id = thread.GetID();
  LLDB_LOG(log, "tid: {0}", thread_id);

  auto it = llvm::find_if(m_threads, [&](const auto &thread_up) {
    return thread_up.get() == &thread;
  });
  assert(it != m_threads.end());
  m_threads.erase(it);

  NotifyTracersOfThreadDestroyed(thread_id);
  SignalIfAllThreadsStopped();
}

void NativeProcessAIX::NotifyTracersProcessStateChanged(
    lldb::StateType state) {
}

Status NativeProcessAIX::NotifyTracersOfNewThread(lldb::tid_t tid) {
  Log *log = GetLog(POSIXLog::Thread);
  Status error;
  return error;
}

Status NativeProcessAIX::NotifyTracersOfThreadDestroyed(lldb::tid_t tid) {
  Log *log = GetLog(POSIXLog::Thread);
  Status error;
  return error;
}

NativeThreadAIX &NativeProcessAIX::AddThread(lldb::tid_t thread_id,
                                                 bool resume) {
  Log *log = GetLog(POSIXLog::Thread);
  LLDB_LOG(log, "pid {0} adding thread with tid {1}", GetID(), thread_id);

  assert(!HasThreadNoLock(thread_id) &&
         "attempted to add a thread by id that already exists");

  // If this is the first thread, save it as the current thread
  if (m_threads.empty())
    SetCurrentThreadID(thread_id);

  m_threads.push_back(std::make_unique<NativeThreadAIX>(*this, thread_id));
  NativeThreadAIX &thread =
      static_cast<NativeThreadAIX &>(*m_threads.back());

  Status tracing_error = NotifyTracersOfNewThread(thread.GetID());
  if (tracing_error.Fail()) {
    thread.SetStoppedByProcessorTrace(tracing_error.AsCString());
    StopRunningThreads(thread.GetID());
  } else if (resume)
    ResumeThread(thread, eStateRunning, LLDB_INVALID_SIGNAL_NUMBER);
  else
    thread.SetStoppedBySignal(SIGSTOP);

  return thread;
}

Status NativeProcessAIX::GetLoadedModuleFileSpec(const char *module_path,
                                                   FileSpec &file_spec) {
  Status error = PopulateMemoryRegionCache();
  if (error.Fail())
    return error;

  FileSpec module_file_spec(module_path);
  FileSystem::Instance().Resolve(module_file_spec);

  file_spec.Clear();
  for (const auto &it : m_mem_region_cache) {
    if (it.second.GetFilename() == module_file_spec.GetFilename()) {
      file_spec = it.second;
      return Status();
    }
  }
  return Status("Module file (%s) not found in /proc/%" PRIu64 "/maps file!",
                module_file_spec.GetFilename().AsCString(), GetID());
}

Status NativeProcessAIX::GetFileLoadAddress(const llvm::StringRef &file_name,
                                              lldb::addr_t &load_addr) {
  load_addr = LLDB_INVALID_ADDRESS;

  NativeThreadAIX &thread = *GetCurrentThread();
  NativeRegisterContextAIX &reg_ctx = thread.GetRegisterContext();

  // FIXME: buffer size
  struct ld_xinfo info[64];
  if (ptrace64(PT_LDXINFO, reg_ctx.GetThread().GetID(), (long long)&(info[0]), sizeof(info), nullptr) == 0) {
    load_addr = (unsigned long)info[0].ldinfo_textorg;
    return Status();
  }
  return Status("No load address found for specified file.");
}

NativeThreadAIX *NativeProcessAIX::GetThreadByID(lldb::tid_t tid) {
  return static_cast<NativeThreadAIX *>(
      NativeProcessProtocol::GetThreadByID(tid));
}

NativeThreadAIX *NativeProcessAIX::GetCurrentThread() {
  return static_cast<NativeThreadAIX *>(
      NativeProcessProtocol::GetCurrentThread());
}

Status NativeProcessAIX::ResumeThread(NativeThreadAIX &thread,
                                        lldb::StateType state, int signo) {
  Log *const log = GetLog(POSIXLog::Thread);
  LLDB_LOG(log, "tid: {0}", thread.GetID());

  // Before we do the resume below, first check if we have a pending stop
  // notification that is currently waiting for all threads to stop.  This is
  // potentially a buggy situation since we're ostensibly waiting for threads
  // to stop before we send out the pending notification, and here we are
  // resuming one before we send out the pending stop notification.
  if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID) {
    LLDB_LOG(log,
             "about to resume tid {0} per explicit request but we have a "
             "pending stop notification (tid {1}) that is actively "
             "waiting for this thread to stop. Valid sequence of events?",
             thread.GetID(), m_pending_notification_tid);
  }

  // Request a resume.  We expect this to be synchronous and the system to
  // reflect it is running after this completes.
  switch (state) {
  case eStateRunning: {
    const auto resume_result = thread.Resume(signo);
    if (resume_result.Success())
      SetState(eStateRunning, true);
    return resume_result;
  }
  case eStateStepping: {
    const auto step_result = thread.SingleStep(signo);
    if (step_result.Success())
      SetState(eStateRunning, true);
    return step_result;
  }
  default:
    LLDB_LOG(log, "Unhandled state {0}.", state);
    llvm_unreachable("Unhandled state for resume");
  }
}

//===----------------------------------------------------------------------===//

void NativeProcessAIX::StopRunningThreads(const lldb::tid_t triggering_tid) {
  Log *const log = GetLog(POSIXLog::Thread);
  LLDB_LOG(log, "about to process event: (triggering_tid: {0})",
           triggering_tid);

  m_pending_notification_tid = triggering_tid;

  // Request a stop for all the thread stops that need to be stopped and are
  // not already known to be stopped.
  for (const auto &thread : m_threads) {
    if (StateIsRunningState(thread->GetState()))
      static_cast<NativeThreadAIX *>(thread.get())->RequestStop();
  }

  SignalIfAllThreadsStopped();
  LLDB_LOG(log, "event processing done");
}

void NativeProcessAIX::SignalIfAllThreadsStopped() {
  if (m_pending_notification_tid == LLDB_INVALID_THREAD_ID)
    return; // No pending notification. Nothing to do.

  for (const auto &thread_sp : m_threads) {
    if (StateIsRunningState(thread_sp->GetState()))
      return; // Some threads are still running. Don't signal yet.
  }

  // We have a pending notification and all threads have stopped.
  Log *log = GetLog(LLDBLog::Process | LLDBLog::Breakpoints);

  // Clear any temporary breakpoints we used to implement software single
  // stepping.
  for (const auto &thread_info : m_threads_stepping_with_breakpoint) {
    Status error = RemoveBreakpoint(thread_info.second);
    if (error.Fail())
      LLDB_LOG(log, "pid = {0} remove stepping breakpoint: {1}",
               thread_info.first, error);
  }
  m_threads_stepping_with_breakpoint.clear();

  // Notify the delegate about the stop
  SetCurrentThreadID(m_pending_notification_tid);
  SetState(StateType::eStateStopped, true);
  m_pending_notification_tid = LLDB_INVALID_THREAD_ID;
}

void NativeProcessAIX::ThreadWasCreated(NativeThreadAIX &thread) {
  Log *const log = GetLog(POSIXLog::Thread);
  LLDB_LOG(log, "tid: {0}", thread.GetID());

  if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID &&
      StateIsRunningState(thread.GetState())) {
    // We will need to wait for this new thread to stop as well before firing
    // the notification.
    thread.RequestStop();
  }
}

static llvm::Optional<WaitStatus> HandlePid(::pid_t pid) {
  Log *log = GetLog(POSIXLog::Process);

  int status;
  ::pid_t wait_pid = llvm::sys::RetryAfterSignal(
      -1, ::waitpid, pid, &status, WNOHANG);

  if (wait_pid == 0)
    return llvm::None;

  if (wait_pid == -1) {
    Status error(errno, eErrorTypePOSIX);
    LLDB_LOG(log, "waitpid({0}, &status, _) failed: {1}", pid,
             error);
    return llvm::None;
  }

  assert(wait_pid == pid);

  WaitStatus wait_status = WaitStatus::Decode(status);

  LLDB_LOG(log, "waitpid({0})  got status = {1}", pid, wait_status);
  return wait_status;
}

void NativeProcessAIX::SigchldHandler() {
  Log *log = GetLog(POSIXLog::Process);

  // Threads can appear or disappear as a result of event processing, so gather
  // the events upfront.
  llvm::DenseMap<lldb::tid_t, WaitStatus> tid_events;
  bool checked_main_thread = false;
  for (const auto &thread_up : m_threads) {
    if (thread_up->GetID() == GetID())
      checked_main_thread = true;

    if (llvm::Optional<WaitStatus> status = HandlePid(thread_up->GetID()))
      tid_events.try_emplace(thread_up->GetID(), *status);
  }
  // Check the main thread even when we're not tracking it as process exit
  // events are reported that way.
  if (!checked_main_thread) {
    if (llvm::Optional<WaitStatus> status = HandlePid(GetID()))
      tid_events.try_emplace(GetID(), *status);
  }

  for (auto &KV : tid_events) {
    LLDB_LOG(log, "processing {0}({1}) ...", KV.first, KV.second);
    if (KV.first == GetID() && (KV.second.type == WaitStatus::Exit ||
                                KV.second.type == WaitStatus::Signal)) {

      // The process exited.  We're done monitoring.  Report to delegate.
      SetExitStatus(KV.second, true);
      return;
    }
    NativeThreadAIX *thread = GetThreadByID(KV.first);
    assert(thread && "Why did this thread disappear?");
    MonitorCallback(*thread, KV.second);
  }
}

#define DECLARE_REGISTER_INFOS_PPC64LE_STRUCT
#include "Plugins/Process/Utility/RegisterInfos_ppc64le.h"
#undef DECLARE_REGISTER_INFOS_PPC64LE_STRUCT

static void GetRegister(lldb::pid_t pid, long long addr, void *buf) {
  uint64_t val = 0;
  ptrace64(PT_READ_GPR, pid, addr, 0, (int *)&val);
  *(uint64_t *)buf = llvm::ByteSwap_64(val);
}

static void SetRegister(lldb::pid_t pid, long long addr, void *buf) {
  uint64_t val = llvm::ByteSwap_64(*(uint64_t *)buf);
  ptrace64(PT_WRITE_GPR, pid, addr, 0, (int *)&val);
}

// Wrapper for ptrace to catch errors and log calls. Note that ptrace sets
// errno on error because -1 can be a valid result (i.e. for PTRACE_PEEK*)
Status NativeProcessAIX::PtraceWrapper(int req, lldb::pid_t pid, void *addr,
                                         void *data, size_t data_size,
                                         long *result) {
  Status error;
  long int ret;

  Log *log = GetLog(POSIXLog::Ptrace);

  PtraceDisplayBytes(req, data, data_size);

  errno = 0;

  if (req == PTRACE_GETREGS) {
    GetRegister(pid, GPR0, &(((GPR *)data)->r0));
    GetRegister(pid, GPR1, &(((GPR *)data)->r1));
    GetRegister(pid, GPR2, &(((GPR *)data)->r2));
    GetRegister(pid, GPR3, &(((GPR *)data)->r3));
    GetRegister(pid, GPR4, &(((GPR *)data)->r4));
    GetRegister(pid, GPR5, &(((GPR *)data)->r5));
    GetRegister(pid, GPR6, &(((GPR *)data)->r6));
    GetRegister(pid, GPR7, &(((GPR *)data)->r7));
    GetRegister(pid, GPR8, &(((GPR *)data)->r8));
    GetRegister(pid, GPR9, &(((GPR *)data)->r9));
    GetRegister(pid, GPR10, &(((GPR *)data)->r10));
    GetRegister(pid, GPR11, &(((GPR *)data)->r11));
    GetRegister(pid, GPR12, &(((GPR *)data)->r12));
    GetRegister(pid, GPR13, &(((GPR *)data)->r13));
    GetRegister(pid, GPR14, &(((GPR *)data)->r14));
    GetRegister(pid, GPR15, &(((GPR *)data)->r15));
    GetRegister(pid, GPR16, &(((GPR *)data)->r16));
    GetRegister(pid, GPR17, &(((GPR *)data)->r17));
    GetRegister(pid, GPR18, &(((GPR *)data)->r18));
    GetRegister(pid, GPR19, &(((GPR *)data)->r19));
    GetRegister(pid, GPR20, &(((GPR *)data)->r20));
    GetRegister(pid, GPR21, &(((GPR *)data)->r21));
    GetRegister(pid, GPR22, &(((GPR *)data)->r22));
    GetRegister(pid, GPR23, &(((GPR *)data)->r23));
    GetRegister(pid, GPR24, &(((GPR *)data)->r24));
    GetRegister(pid, GPR25, &(((GPR *)data)->r25));
    GetRegister(pid, GPR26, &(((GPR *)data)->r26));
    GetRegister(pid, GPR27, &(((GPR *)data)->r27));
    GetRegister(pid, GPR28, &(((GPR *)data)->r28));
    GetRegister(pid, GPR29, &(((GPR *)data)->r29));
    GetRegister(pid, GPR30, &(((GPR *)data)->r30));
    GetRegister(pid, GPR31, &(((GPR *)data)->r31));
    GetRegister(pid, IAR, &(((GPR *)data)->pc));
    GetRegister(pid, MSR, &(((GPR *)data)->msr));
    //FIXME: origr3/softe/trap on AIX?
    GetRegister(pid, CTR, &(((GPR *)data)->ctr));
    GetRegister(pid, LR, &(((GPR *)data)->lr));
    GetRegister(pid, XER, &(((GPR *)data)->xer));
    GetRegister(pid, CR, &(((GPR *)data)->cr));
  } else if (req == PTRACE_SETREGS) {
    SetRegister(pid, GPR0, &(((GPR *)data)->r0));
    SetRegister(pid, GPR1, &(((GPR *)data)->r1));
    SetRegister(pid, GPR2, &(((GPR *)data)->r2));
    SetRegister(pid, GPR3, &(((GPR *)data)->r3));
    SetRegister(pid, GPR4, &(((GPR *)data)->r4));
    SetRegister(pid, GPR5, &(((GPR *)data)->r5));
    SetRegister(pid, GPR6, &(((GPR *)data)->r6));
    SetRegister(pid, GPR7, &(((GPR *)data)->r7));
    SetRegister(pid, GPR8, &(((GPR *)data)->r8));
    SetRegister(pid, GPR9, &(((GPR *)data)->r9));
    SetRegister(pid, GPR10, &(((GPR *)data)->r10));
    SetRegister(pid, GPR11, &(((GPR *)data)->r11));
    SetRegister(pid, GPR12, &(((GPR *)data)->r12));
    SetRegister(pid, GPR13, &(((GPR *)data)->r13));
    SetRegister(pid, GPR14, &(((GPR *)data)->r14));
    SetRegister(pid, GPR15, &(((GPR *)data)->r15));
    SetRegister(pid, GPR16, &(((GPR *)data)->r16));
    SetRegister(pid, GPR17, &(((GPR *)data)->r17));
    SetRegister(pid, GPR18, &(((GPR *)data)->r18));
    SetRegister(pid, GPR19, &(((GPR *)data)->r19));
    SetRegister(pid, GPR20, &(((GPR *)data)->r20));
    SetRegister(pid, GPR21, &(((GPR *)data)->r21));
    SetRegister(pid, GPR22, &(((GPR *)data)->r22));
    SetRegister(pid, GPR23, &(((GPR *)data)->r23));
    SetRegister(pid, GPR24, &(((GPR *)data)->r24));
    SetRegister(pid, GPR25, &(((GPR *)data)->r25));
    SetRegister(pid, GPR26, &(((GPR *)data)->r26));
    SetRegister(pid, GPR27, &(((GPR *)data)->r27));
    SetRegister(pid, GPR28, &(((GPR *)data)->r28));
    SetRegister(pid, GPR29, &(((GPR *)data)->r29));
    SetRegister(pid, GPR30, &(((GPR *)data)->r30));
    SetRegister(pid, GPR31, &(((GPR *)data)->r31));
    SetRegister(pid, IAR, &(((GPR *)data)->pc));
    SetRegister(pid, MSR, &(((GPR *)data)->msr));
    //FIXME: origr3/softe/trap on AIX?
    SetRegister(pid, CTR, &(((GPR *)data)->ctr));
    SetRegister(pid, LR, &(((GPR *)data)->lr));
    SetRegister(pid, XER, &(((GPR *)data)->xer));
    SetRegister(pid, CR, &(((GPR *)data)->cr));
  } else if (req < PT_COMMAND_MAX) {
    if (req == PT_CONTINUE) {
      int buf;
      ptrace64(req, pid, 1, 0, &buf);
    } else if (req == PT_READ_BLOCK) {
      ptrace64(req, pid, (long long)addr, (int)data_size, (int *)result);
    } else if (req == PT_WRITE_BLOCK) {
      ptrace64(req, pid, (long long)addr, (int)data_size, (int *)result);
    } else if (req == PT_ATTACH) {
      ptrace64(req, pid, 0, 0, nullptr);
    } else {
      assert(0 && "Not supported yet.");
    }
  } else {
    assert(0 && "Not supported yet.");
  }

  if (errno) {
    error.SetErrorToErrno();
    ret = -1;
  }

  LLDB_LOG(log, "ptrace({0}, {1}, {2}, {3}, {4})={5:x}", req, pid, addr, data,
           data_size, ret);

  PtraceDisplayBytes(req, data, data_size);

  if (error.Fail())
    LLDB_LOG(log, "ptrace() failed: {0}", error);

  return error;
}

llvm::Expected<TraceSupportedResponse> NativeProcessAIX::TraceSupported() {
  return NativeProcessProtocol::TraceSupported();
}

Error NativeProcessAIX::TraceStart(StringRef json_request, StringRef type) {
  return NativeProcessProtocol::TraceStart(json_request, type);
}

Error NativeProcessAIX::TraceStop(const TraceStopRequest &request) {
  return NativeProcessProtocol::TraceStop(request);
}

Expected<json::Value> NativeProcessAIX::TraceGetState(StringRef type) {
  return NativeProcessProtocol::TraceGetState(type);
}

Expected<std::vector<uint8_t>> NativeProcessAIX::TraceGetBinaryData(
    const TraceGetBinaryDataRequest &request) {
  return NativeProcessProtocol::TraceGetBinaryData(request);
}
