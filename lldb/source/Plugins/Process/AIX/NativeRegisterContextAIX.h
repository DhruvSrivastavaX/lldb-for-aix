//===-- NativeRegisterContextAIX.h ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef lldb_NativeRegisterContextAIX_h
#define lldb_NativeRegisterContextAIX_h

#include "Plugins/Process/Utility/NativeRegisterContextRegisterInfo.h"
#include "lldb/Host/common/NativeThreadProtocol.h"
#include "lldb/Target/MemoryTagManager.h"
#include "llvm/Support/Error.h"

namespace lldb_private {
namespace process_aix {

class NativeThreadAIX;

class NativeRegisterContextAIX
    : public virtual NativeRegisterContextRegisterInfo {
public:
  // This function is implemented in the NativeRegisterContextAIX_* subclasses
  // to create a new instance of the host specific NativeRegisterContextAIX.
  // The implementations can't collide as only one NativeRegisterContextAIX_*
  // variant should be compiled into the final executable.
  static std::unique_ptr<NativeRegisterContextAIX>
  CreateHostNativeRegisterContextAIX(const ArchSpec &target_arch,
                                       NativeThreadAIX &native_thread);

  // Invalidates cached values in register context data structures
  virtual void InvalidateAllRegisters(){}

  struct SyscallData {
    /// The syscall instruction. If the architecture uses software
    /// single-stepping, the instruction should also be followed by a trap to
    /// ensure the process is stopped after the syscall.
    llvm::ArrayRef<uint8_t> Insn;

    /// Registers used for syscall arguments. The first register is used to
    /// store the syscall number.
    llvm::ArrayRef<uint32_t> Args;

    uint32_t Result; ///< Register containing the syscall result.
  };
  /// Return architecture-specific data needed to make inferior syscalls, if
  /// they are supported.
  virtual std::optional<SyscallData> GetSyscallData() { return std::nullopt; }

  struct MmapData {
    // Syscall numbers can be found (e.g.) in /usr/include/asm/unistd.h for the
    // relevant architecture.
    unsigned SysMmap;   ///< mmap syscall number.
    unsigned SysMunmap; ///< munmap syscall number
  };
  /// Return the architecture-specific data needed to make mmap syscalls, if
  /// they are supported.
  virtual std::optional<MmapData> GetMmapData() { return std::nullopt; }

  struct MemoryTaggingDetails {
    /// Object with tag handling utilities. If the function below returns
    /// a valid structure, you can assume that this pointer is valid.
    std::unique_ptr<MemoryTagManager> manager;
    int ptrace_read_req;  /// ptrace operation number for memory tag read
    int ptrace_write_req; /// ptrace operation number for memory tag write
  };
  /// Return architecture specific data needed to use memory tags,
  /// if they are supported.
  virtual llvm::Expected<MemoryTaggingDetails>
  GetMemoryTaggingDetails(int32_t type) {
    return llvm::createStringError(
        llvm::inconvertibleErrorCode(),
        "Architecture does not support memory tagging");
  }

protected:
  // NB: This constructor is here only because gcc<=6.5 requires a virtual base
  // class initializer on abstract class (even though it is never used). It can
  // be deleted once we move to gcc>=7.0.
  NativeRegisterContextAIX(NativeThreadProtocol &thread)
      : NativeRegisterContextRegisterInfo(thread, nullptr) {}

  lldb::ByteOrder GetByteOrder() const;

  virtual Status ReadRegisterRaw(uint32_t reg_index, RegisterValue &reg_value);

  virtual Status WriteRegisterRaw(uint32_t reg_index,
                                  const RegisterValue &reg_value);

  virtual Status ReadRegisterSet(void *buf, size_t buf_size,
                                 unsigned int regset);

  virtual Status WriteRegisterSet(void *buf, size_t buf_size,
                                  unsigned int regset);

  virtual Status ReadGPR();

  virtual Status WriteGPR();

  virtual Status ReadFPR();

  virtual Status WriteFPR();

  virtual void *GetGPRBuffer() = 0;

  virtual size_t GetGPRSize() const {
    return GetRegisterInfoInterface().GetGPRSize();
  }

  virtual void *GetFPRBuffer() = 0;

  virtual size_t GetFPRSize() = 0;

  virtual uint32_t GetPtraceOffset(uint32_t reg_index) {
    return GetRegisterInfoAtIndex(reg_index)->byte_offset;
  }

  // The Do*** functions are executed on the privileged thread and can perform
  // ptrace
  // operations directly.
  virtual Status DoReadRegisterValue(uint32_t offset, const char *reg_name,
                                     uint32_t size, RegisterValue &value);

  virtual Status DoWriteRegisterValue(uint32_t offset, const char *reg_name,
                                      const RegisterValue &value);
};

} // namespace process_aix
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextAIX_h
