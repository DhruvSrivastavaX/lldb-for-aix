//===-- NativeRegisterContextAIX_ppc64.h --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// This implementation is related to the OpenPOWER ABI for Power Architecture
// 64-bit ELF V2 ABI

#if defined(__powerpc64__)

#ifndef lldb_NativeRegisterContextAIX_ppc64_h
#define lldb_NativeRegisterContextAIX_ppc64_h

#include "Plugins/Process/AIX/NativeRegisterContextAIX.h"
#include "Plugins/Process/Utility/lldb-ppc64le-register-enums.h"

#define DECLARE_REGISTER_INFOS_PPC64LE_STRUCT
#include "Plugins/Process/Utility/RegisterInfos_ppc64le.h"
#undef DECLARE_REGISTER_INFOS_PPC64LE_STRUCT
typedef struct _GPR32 {
  uint32_t r0;
  uint32_t r1;
  uint32_t r2;
  uint32_t r3;
  uint32_t r4;
  uint32_t r5;
  uint32_t r6;
  uint32_t r7;
  uint32_t r8;
  uint32_t r9;
  uint32_t r10;
  uint32_t r11;
  uint32_t r12;
  uint32_t r13;
  uint32_t r14;
  uint32_t r15;
  uint32_t r16;
  uint32_t r17;
  uint32_t r18;
  uint32_t r19;
  uint32_t r20;
  uint32_t r21;
  uint32_t r22;
  uint32_t r23;
  uint32_t r24;
  uint32_t r25;
  uint32_t r26;
  uint32_t r27;
  uint32_t r28;
  uint32_t r29;
  uint32_t r30;
  uint32_t r31;
  uint32_t pc;
  uint32_t msr;
  uint32_t origr3;
  uint32_t ctr;
  uint32_t lr;
  uint32_t xer;
  uint32_t cr;
  uint32_t softe;
  uint32_t trap;
} GPR32;
namespace lldb_private {
namespace process_aix {

class NativeProcessAIX;

class NativeRegisterContextAIX_ppc64 : public NativeRegisterContextAIX {
public:
  NativeRegisterContextAIX_ppc64(const ArchSpec &target_arch,
                                     NativeThreadProtocol &native_thread);

  uint32_t GetRegisterSetCount() const override;

  uint32_t GetUserRegisterCount() const override;

  const RegisterSet *GetRegisterSet(uint32_t set_index) const override;

  Status ReadRegister(const RegisterInfo *reg_info,
                      RegisterValue &reg_value) override;

  Status WriteRegister(const RegisterInfo *reg_info,
                       const RegisterValue &reg_value) override;

  Status ReadAllRegisterValues(lldb::WritableDataBufferSP &data_sp) override;

  Status WriteAllRegisterValues(const lldb::DataBufferSP &data_sp) override;

  // Hardware watchpoint management functions

  uint32_t NumSupportedHardwareWatchpoints() override;

  uint32_t SetHardwareWatchpoint(lldb::addr_t addr, size_t size,
                                 uint32_t watch_flags) override;

  bool ClearHardwareWatchpoint(uint32_t hw_index) override;

  Status GetWatchpointHitIndex(uint32_t &wp_index,
                               lldb::addr_t trap_addr) override;

  lldb::addr_t GetWatchpointHitAddress(uint32_t wp_index) override;

  lldb::addr_t GetWatchpointAddress(uint32_t wp_index) override;

  uint32_t GetWatchpointSize(uint32_t wp_index);

  bool WatchpointIsEnabled(uint32_t wp_index);

protected:
  bool IsVMX(unsigned reg);

  bool IsVSX(unsigned reg);

  Status ReadVMX();

  Status WriteVMX();

  Status ReadVSX();

  Status WriteVSX();

  void *GetGPRBuffer() override { return &m_gpr_ppc64le; }
  void *GetGPR32Buffer() { return &m_gpr_ppc32le; }

  void *GetFPRBuffer() override { return &m_fpr_ppc64le; }

  size_t GetFPRSize() override { return sizeof(m_fpr_ppc64le); }

private:
  GPR32 m_gpr_ppc32le; // 64-bit general purpose registers.
  GPR m_gpr_ppc64le; // 64-bit general purpose registers.
  FPR m_fpr_ppc64le; // floating-point registers including extended register.
  VMX m_vmx_ppc64le; // VMX registers.
  VSX m_vsx_ppc64le; // Last lower bytes from first VSX registers.

  bool IsGPR(unsigned reg) const;

  bool IsFPR(unsigned reg) const;

  bool IsVMX(unsigned reg) const;

  bool IsVSX(unsigned reg) const;

  uint32_t CalculateFprOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVmxOffset(const RegisterInfo *reg_info) const;

  uint32_t CalculateVsxOffset(const RegisterInfo *reg_info) const;

  Status ReadHardwareDebugInfo();

  Status WriteHardwareDebugRegs();

  // Debug register info for hardware watchpoints management.
  struct DREG {
    lldb::addr_t address;   // Breakpoint/watchpoint address value.
    lldb::addr_t hit_addr;  // Address at which last watchpoint trigger
                            // exception occurred.
    lldb::addr_t real_addr; // Address value that should cause target to stop.
    uint32_t control;       // Breakpoint/watchpoint control value.
    uint32_t refcount;      // Serves as enable/disable and reference counter.
    long slot;              // Saves the value returned from PTRACE_SETHWDEBUG.
    int mode;               // Defines if watchpoint is read/write/access.
  };

  std::array<DREG, 4> m_hwp_regs;

  // 16 is just a maximum value, query hardware for actual watchpoint count
  uint32_t m_max_hwp_supported = 16;
  uint32_t m_max_hbp_supported = 16;
  bool m_refresh_hwdebug_info = true;
};

} // namespace process_aix
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextAIX_ppc64_h

#endif // defined(__powerpc64__)
