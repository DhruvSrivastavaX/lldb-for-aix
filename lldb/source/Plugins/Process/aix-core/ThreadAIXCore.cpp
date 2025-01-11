//===-- ThreadAIXCore.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/StopInfo.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/UnixSignals.h"
#include "lldb/Target/Unwind.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/ProcessInfo.h"

#include "Plugins/Process/Utility/RegisterContextPOSIX_powerpc.h"
#include "Plugins/Process/Utility/RegisterContextPOSIX_ppc64le.h"
#include "Plugins/Process/Utility/RegisterInfoPOSIX_ppc64le.h"
#include "Plugins/Process/elf-core/RegisterContextPOSIXCore_powerpc.h"

#include "ProcessAIXCore.h"
#include "AIXCore.h"
#include "ThreadAIXCore.h"

#include <memory>
#include <iostream>

using namespace lldb;
using namespace lldb_private;

// Construct a Thread object with given data
ThreadAIXCore::ThreadAIXCore(Process &process, const ThreadData &td)
    : Thread(process, td.tid), m_thread_name(td.name), m_thread_reg_ctx_sp(),
      m_gpregset_data(td.gpregset),
      m_siginfo(std::move(td.siginfo)) {}

ThreadAIXCore::~ThreadAIXCore() { DestroyThread(); }

void ThreadAIXCore::RefreshStateAfterStop() {
  GetRegisterContext()->InvalidateIfNeeded(false);
}

RegisterContextSP ThreadAIXCore::GetRegisterContext() {
  if (!m_reg_context_sp) {
    m_reg_context_sp = CreateRegisterContextForFrame(nullptr);
  }
  return m_reg_context_sp;
}

RegisterContextSP
ThreadAIXCore::CreateRegisterContextForFrame(StackFrame *frame) {
  std::cout << "ThreadCore::" <<__FUNCTION__ << std::endl;
  RegisterContextSP reg_ctx_sp;
  uint32_t concrete_frame_idx = 0;
  Log *log = GetLog(LLDBLog::Thread);

  if (frame)
    concrete_frame_idx = frame->GetConcreteFrameIndex();

  bool is_linux = false;
  if (concrete_frame_idx == 0) {
    if (m_thread_reg_ctx_sp)
      return m_thread_reg_ctx_sp;

    ProcessAIXCore *process = static_cast<ProcessAIXCore *>(GetProcess().get());
    ArchSpec arch = process->GetArchitecture();
    RegisterInfoInterface *reg_interface = nullptr;

   // switch (arch.GetTriple().getOS()) {
     //   case llvm::Triple::AIX: {
       // switch(arch.GetMachine()) {
         //   case llvm::Triple::ppc64:
              //  reg_interface = new RegisterContextPOSIX_powerpc(arch);
           //     break;
          //  default:
           //     break;
      //  }
       // break;
     // }
     //  default:
      //  break;
  //  }
    switch (arch.GetMachine()) {
        case llvm::Triple::ppc64:
            reg_interface = new RegisterInfoPOSIX_ppc64le(arch);
            m_thread_reg_ctx_sp = std::make_shared<RegisterContextCorePOSIX_powerpc>(
                    *this, reg_interface, m_gpregset_data, m_notes);
            break;
        default:
            break;
    }
    reg_ctx_sp = m_thread_reg_ctx_sp;
  std::cout << "ThreadCore::" <<__FUNCTION__ << "IF RegisterContext "<<std::endl;
    } else {
        reg_ctx_sp = GetUnwinder().CreateRegisterContextForFrame(frame);
  std::cout << "ThreadCore::" <<__FUNCTION__ << "ELSE RegisterContext "<<std::endl;
    }
  return reg_ctx_sp;
}

bool ThreadAIXCore::CalculateStopInfo() {
  std::cout << "ThreadCore::" <<__FUNCTION__ << std::endl;
  ProcessSP process_sp(GetProcess());
  if (!process_sp)
    return false;

  lldb::UnixSignalsSP unix_signals_sp(process_sp->GetUnixSignals());
  if (!unix_signals_sp)
    return false;

  m_siginfo.si_signo = 11; // ******************************************
  const char *sig_description;
  std::string description = "Random String";//m_siginfo.GetDescription(*unix_signals_sp);
  if (description.empty())
    sig_description = nullptr;
  else
    sig_description = description.c_str();

  SetStopInfo(StopInfo::CreateStopReasonWithSignal(
      *this, m_siginfo.si_signo, sig_description, m_siginfo.si_code));

  SetStopInfo(m_stop_info_sp);
  return true;
}

void AIXSigInfo::Parse(const AIXCORE::AIXCore64Header data, const ArchSpec &arch,
                              const lldb_private::UnixSignals &unix_signals) {
    Log *log = GetLog(LLDBLog::Process);
    LLDB_LOGF(log, "c_signo: %x, c_flag: %x, c_entries: %x, c_version: %x",
            data.c_signo,
            data.c_flag, data.c_entries, data.c_version);
    //si_signo = c_signo;
}

AIXSigInfo::AIXSigInfo() { memset(this, 0, sizeof(AIXSigInfo)); }

size_t AIXSigInfo::GetSize(const lldb_private::ArchSpec &arch) {
    return sizeof(AIXSigInfo);
}
