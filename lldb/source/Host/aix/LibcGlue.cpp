//===-- LibcGlue.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// This file adds functions missing from libc on older versions of aix

#include <cerrno>
#include <lldb/Host/aix/Uio.h>
#include <unistd.h>

#if !HAVE_PROCESS_VM_READV
// If the syscall wrapper is not available, provide one.
ssize_t process_vm_readv(::pid_t pid, const struct iovec *local_iov,
                         unsigned long liovcnt, const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags) {
#if HAVE_NR_PROCESS_VM_READV
  // If we have the syscall number, we can issue the syscall ourselves.
  //return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov,
  //               riovcnt, flags);
  return 0;
#else // If not, let's pretend the syscall is not present.
  errno = ENOSYS;
  return -1;
#endif
}
#endif
