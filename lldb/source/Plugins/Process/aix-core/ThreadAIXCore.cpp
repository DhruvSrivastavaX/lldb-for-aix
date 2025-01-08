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

void AIXSigInfo::Parse(const AIXCORE::AIXCore64Header data, const ArchSpec &arch,
                              const lldb_private::UnixSignals &unix_signals) {
  std::cout << "HEADER DATA: " << data.c_signo << " bla " << data.c_version << std::endl; 
    Log *log = GetLog(LLDBLog::Process);
    LLDB_LOGF(log, "c_signo: %x, c_flag: %x, c_entries: %x, c_version: %x",
            data.c_signo,
            data.c_flag, data.c_entries, data.c_version);
}

AIXSigInfo::AIXSigInfo() { memset(this, 0, sizeof(AIXSigInfo)); }

size_t AIXSigInfo::GetSize(const lldb_private::ArchSpec &arch) {
    return sizeof(AIXSigInfo);
}
