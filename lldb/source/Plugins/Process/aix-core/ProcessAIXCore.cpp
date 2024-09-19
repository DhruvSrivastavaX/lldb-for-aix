//===-- ProcessAIXCore.cpp ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <cstdlib>

#include <memory>
#include <mutex>

#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Section.h"
#include "lldb/Target/ABI.h"
#include "lldb/Target/DynamicLoader.h"
#include "lldb/Target/MemoryRegionInfo.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/UnixSignals.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/State.h"

#include "llvm/Support/Threading.h"

#include "AIXCore.h"
#include "ProcessAIXCore.h"

using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ProcessAIXCore)

llvm::StringRef ProcessAIXCore::GetPluginDescriptionStatic() {
  return "AIX core dump plug-in.";
}

void ProcessAIXCore::Initialize() {
  static llvm::once_flag g_once_flag;

  Log *log = GetLog(LLDBLog::Process);
  if (log) {
      LLDB_LOGF(log, "Init Plugin for AIX Core");
  }
  llvm::call_once(g_once_flag, []() {
    PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                  GetPluginDescriptionStatic(), CreateInstance);
  });
}

void ProcessAIXCore::Terminate() {
  PluginManager::UnregisterPlugin(ProcessAIXCore::CreateInstance);
}

lldb::ProcessSP ProcessAIXCore::CreateInstance(lldb::TargetSP target_sp,
                                               lldb::ListenerSP listener_sp,
                                               const FileSpec *crash_file,
                                               bool can_connect) {
  lldb::ProcessSP process_sp;
  Log *log = GetLog(LLDBLog::Process);
  if (crash_file && !can_connect) {
      const size_t header_size = sizeof(AIXCORE::Core64_AIX_Hdr);

      if (log) {
          LLDB_LOGF(log, "Core Header Size: %zu", header_size);
      }
      auto data_sp = FileSystem::Instance().CreateDataBuffer(
              crash_file->GetPath(), header_size, 0);
      LLDB_LOGF(log, "Core Header Size: %p", data_sp.get());
      LLDB_LOGF(log, "Core Header Size: %.*s", (crash_file->GetPath().size(),
                  crash_file->GetPath().data()));
      if (data_sp && data_sp->GetByteSize() == header_size) {
          process_sp = std::make_shared<ProcessAIXCore>(target_sp, listener_sp,
                  *crash_file);
          LLDB_LOGF(log, "Core Header Size: Created!! ");
      }

  }
  if (log) {
      LLDB_LOGF(log, "Called CreateInstance for AIX Core");
  }
  return process_sp;
}

// ProcessAIXCore constructor
ProcessAIXCore::ProcessAIXCore(lldb::TargetSP target_sp,
                               lldb::ListenerSP listener_sp,
                               const FileSpec &core_file)
    : PostMortemProcess(target_sp, listener_sp, core_file) {}

// Destructor
ProcessAIXCore::~ProcessAIXCore() {
  // We need to call finalize on the process before destroying ourselves to
  // make sure all of the broadcaster cleanup goes as planned. If we destruct
  // this class, then Process::~Process() might have problems trying to fully
  // destroy the broadcaster.
  Finalize(true /* destructing */);
}

bool ProcessAIXCore::CanDebug(lldb::TargetSP target_sp,
                                bool plugin_specified_by_name) {

    Log *log = GetLog(LLDBLog::Process);
    if (log) {
        LLDB_LOGF(log, "CanDebug Called ");
    }
    return true;

}

bool ProcessAIXCore::DoUpdateThreadList(ThreadList &old_thread_list,
                                        ThreadList &new_thread_list) 
{ return false; } 

void ProcessAIXCore::RefreshStateAfterStop() {}

size_t ProcessAIXCore::DoReadMemory(lldb::addr_t addr, void *buf, size_t size,
                                    Status &error) { return 0; }

Status ProcessAIXCore::DoDestroy() { return Status(); }
