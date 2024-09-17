//===-- ProcessAIXCore.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// Notes about Linux Process core dumps:
//  1) Linux core dump is stored as AIX file.
//  2) The AIX file's PT_NOTE and PT_LOAD segments describes the program's
//     address space and thread contexts.
//  3) PT_NOTE segment contains note entries which describes a thread context.
//  4) PT_LOAD segment describes a valid contiguous range of process address
//     space.
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_AIX_CORE_PROCESSAIXCORE_H
#define LLDB_SOURCE_PLUGINS_PROCESS_AIX_CORE_PROCESSAIXCORE_H

#include <list>
#include <vector>

#include "lldb/Target/PostMortemProcess.h"
#include "lldb/Utility/Status.h"

struct ThreadData;

class ProcessAIXCore : public lldb_private::PostMortemProcess {
public:
  // Constructors and Destructors
  static lldb::ProcessSP
  CreateInstance(lldb::TargetSP target_sp, lldb::ListenerSP listener_sp,
                 const lldb_private::FileSpec *crash_file_path,
                 bool can_connect);

  static void Initialize();

  static void Terminate();

  static llvm::StringRef GetPluginNameStatic() { return "aix-core"; }

  static llvm::StringRef GetPluginDescriptionStatic();

  // Constructors and Destructors
  ProcessAIXCore(lldb::TargetSP target_sp, lldb::ListenerSP listener_sp,
                 const lldb_private::FileSpec &core_file);

  ~ProcessAIXCore() override;

  // PluginInterface protocol
  llvm::StringRef GetPluginName() override { return GetPluginNameStatic(); }

  // Process Control
  lldb_private::Status DoDestroy() override;

  lldb_private::Status WillResume() override {
    return lldb_private::Status::FromErrorStringWithFormatv(
        "error: {0} does not support resuming processes", GetPluginName());
  }

  bool WarnBeforeDetach() const override { return false; }

  lldb_private::ArchSpec GetArchitecture();

protected:
private:
  lldb::ModuleSP m_core_module_sp;
  std::string m_dyld_plugin_name;

  // True if m_thread_contexts contains valid entries
  bool m_thread_data_valid = false;
};

#endif // LLDB_SOURCE_PLUGINS_PROCESS_AIX_CORE_PROCESSAIXCORE_H
