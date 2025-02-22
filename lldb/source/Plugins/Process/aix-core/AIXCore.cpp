// AIXCore.cpp
// Add prologue 
//

#include <cstring>

#include "lldb/Core/Section.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Stream.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/State.h"

#include "AIXCore.h"
#if defined(_AIX)
#include <sys/ldr.h>
#endif
#include <iostream>

using namespace AIXCORE;
using namespace lldb;
using namespace lldb_private;

AIXCore64Header::AIXCore64Header() { memset(this, 0, sizeof(AIXCore64Header)); }


bool AIXCore64Header::ParseLoaderData(lldb_private::DataExtractor &data,
                lldb::offset_t *offset) {
    Log *log = GetLog(LLDBLog::DynamicLoader);
    LLDB_LOGF(log, "Loader OFFSET: %d", *offset);
    struct ld_info ldinfo[64];
    ldinfo[0].ldinfo_next = data.GetU32(offset);
    LLDB_LOGF(log, "ldinfo_next: %x", ldinfo[0].ldinfo_next);
    return true;
}
bool AIXCore64Header::ParseRegisterContext(lldb_private::DataExtractor &data,
                lldb::offset_t *offset) {
    Log *log = GetLog(LLDBLog::Process);
    // The data is arranged in this order in this coredump file
    // so we have to fetch in this exact order. But need to change
    // the context structure order according to Infos_ppc64
    for(int i = 0; i < 32; i++)
        c_flt.context.gpr[i] = data.GetU64(offset);
    c_flt.context.msr = data.GetU64(offset); 
    c_flt.context.iar = data.GetU64(offset); 
    c_flt.context.lr = data.GetU64(offset); 
    c_flt.context.ctr = data.GetU64(offset); 
    c_flt.context.cr = data.GetU32(offset); 
    c_flt.context.xer = data.GetU32(offset); 
    c_flt.context.fpscr = data.GetU32(offset); 
    c_flt.context.fpscrx = data.GetU32(offset); 
    c_flt.context.except[0] = data.GetU64(offset); 
    for(int i = 0; i < 32; i++)
        c_flt.context.fpr[i] = data.GetU64(offset);
    c_flt.context.fpeu = data.GetU8(offset); 
    c_flt.context.fpinfo = data.GetU8(offset); 
    c_flt.context.fpscr24_31 = data.GetU8(offset); 
    c_flt.context.pad[0] = data.GetU8(offset); 
    c_flt.context.excp_type = data.GetU32(offset); 
    std::cout << "GPR: " /*<< std::hex*/ << c_flt.context.gpr[0] <<" " << 
        c_flt.context.gpr[1] << " " << c_flt.context.gpr[2] << std::endl; 
    std::cout << "msr, iar, lr: " << /*std::hex <<*/ c_flt.context.msr <<" " << 
        c_flt.context.iar << " " << c_flt.context.lr << std::endl; 

    return true;
}
bool AIXCore64Header::ParseThreadContext(lldb_private::DataExtractor &data,
                lldb::offset_t *offset) {

    Log *log = GetLog(LLDBLog::Process);
    lldb::offset_t offset_to_regctx = *offset; 
    offset_to_regctx += 424;
    LLDB_LOGF(log, "OFFSET: %d", *offset); 
    LLDB_LOGF(log, "OFFSET_TO_REG: %d", offset_to_regctx); 
    c_flt.threadEntry.ti_tid = data.GetU64(offset);
    c_flt.threadEntry.ti_pid = data.GetU32(offset);
    LLDB_LOGF(log, "ti_tid: %lu, ti_pid: %d", c_flt.threadEntry.ti_tid,
            c_flt.threadEntry.ti_pid);
    int ret = ParseRegisterContext(data, &offset_to_regctx);
    return true;
}
 
bool AIXCore64Header::ParseUserData(lldb_private::DataExtractor &data,
                lldb::offset_t *offset) {
    Log *log = GetLog(LLDBLog::Process);
    c_user.process.pi_pid = data.GetU32(offset); 
    c_user.process.pi_ppid = data.GetU32(offset); 
    c_user.process.pi_sid = data.GetU32(offset); 
    c_user.process.pi_pgrp = data.GetU32(offset); 
    c_user.process.pi_uid = data.GetU32(offset); 
    c_user.process.pi_suid = data.GetU32(offset); 

    c_user.process.pi_ttyp = data.GetU32(offset); 
    c_user.process.pi_pad0 = data.GetU32(offset); 
    c_user.process.pi_ttyd = data.GetU64(offset); 
    c_user.process.pi_ttympx = data.GetU64(offset);

    c_user.process.pi_nice = data.GetU32(offset); 
    c_user.process.pi_state = data.GetU32(offset); 
    c_user.process.pi_flags = data.GetU32(offset); 
    c_user.process.pi_flags2 = data.GetU32(offset); 
    c_user.process.pi_thcount = data.GetU32(offset); 
    c_user.process.pi_cpu = data.GetU32(offset); 
    c_user.process.pi_pri = data.GetU32(offset);

    c_user.process.pi_maxofile = data.GetU32(offset);
    c_user.process.pi_cdir = data.GetU64(offset);
    c_user.process.pi_rdir = data.GetU64(offset);
    c_user.process.pi_cmask = data.GetU16(offset);
    c_user.process.pi_pad1 = data.GetU16(offset);

    ByteOrder byteorder = data.GetByteOrder();
    size_t size = 33;
    data.ExtractBytes(*offset, size, byteorder, c_user.process.pi_comm);
    offset += size;

    LLDB_LOGF(log, "pid: %d, ppid: %d", c_user.process.pi_pid, c_user.process.pi_ppid); 
    LLDB_LOGF(log, "name: %s", c_user.process.pi_comm); 
    return true;
}

bool AIXCore64Header::ParseCoreHeader(lldb_private::DataExtractor &data,
                            lldb::offset_t *offset) {

    Log *log = GetLog(LLDBLog::Process);
    //if(data.GetU8(offset,  &c_signo, 1) == nullptr)
      //  return false;
    LLDB_LOGF(log, "OFFSET: %d", *offset); 
    c_signo = data.GetU8(offset);  
    c_flag = data.GetU8(offset);  
    c_entries = data.GetU16(offset);  
    c_version = data.GetU32(offset);
    LLDB_LOGF(log, "c_signo: %x, c_flag: %x, c_entries: %x, c_version: %x",
            c_signo,
            c_flag, c_entries, c_version);
    c_fdsinfox = data.GetU64(offset);

    c_loader = data.GetU64(offset);
    c_lsize = data.GetU64(offset);
    c_n_thr = data.GetU32(offset);
    c_reserved0 = data.GetU32(offset);
    c_thr = data.GetU64(offset);
    c_segs = data.GetU64(offset);
    c_segregion = data.GetU64(offset);
    c_stack = data.GetU64(offset);
    c_stackorg = data.GetU64(offset);
    c_size = data.GetU64(offset);
    c_data = data.GetU64(offset);
    c_dataorg = data.GetU64(offset);
    c_datasize = data.GetU64(offset);
    c_sdorg = data.GetU64(offset);
    c_sdsize = data.GetU64(offset);
    c_vmregions = data.GetU64(offset);
    c_vmm = data.GetU64(offset);
    c_impl = data.GetU32(offset);
    c_n_extctx = data.GetU32(offset);
    c_cprs = data.GetU64(offset);
    c_extctx = data.GetU64(offset);
    c_ukeyctx = data.GetU64(offset);
    c_loader2 = data.GetU64(offset);
    c_lsize2 = data.GetU64(offset);
    c_extproc = data.GetU64(offset);
    c_reserved[0] = data.GetU64(offset);
    c_reserved[1] = data.GetU64(offset);



    LLDB_LOGF(log, "Size of just header vars %d", sizeof(struct AIXCore64Header) - sizeof(ThreadContext64) - sizeof(UserData));
    LLDB_LOGF(log, "All Sizes: AIXCore64Header: %d, ThreadContext64: %d, UserData: %d",
            sizeof(AIXCore64Header), sizeof(ThreadContext64), sizeof(UserData));
    LLDB_LOGF(log, "c_fdsinfox %x, c_loader %x, c_lsize %x, c_n_thr %x, c_reserved0 %x, c_thr %x",
			c_fdsinfox, c_loader, c_lsize, c_n_thr, c_reserved0, c_thr);   
    LLDB_LOGF(log, "c_segsi %x, c_segregion %x, c_stack %x, c_stackorg %x, c_size %x, c_data %x, c_dataorg %x, c_datasize %x",c_segs, c_segregion, c_stack, c_stackorg, c_size, c_data, c_dataorg, 
c_datasize);
    LLDB_LOGF(log, "OFFSET: %d", *offset); 
    lldb::offset_t offset_to_user = (*offset + 1000); // There is a size mismatch in aix vs lldb structures here, TODO:
    lldb::offset_t offset_to_loader = c_loader; // There is a size mismatch in aix vs lldb structures here, TODO:
    int ret = 0;
    ret = ParseThreadContext(data, offset);
    LLDB_LOGF(log, "OFFSET: %d", *offset); 
    LLDB_LOGF(log, "c_loader: %d, c_lsize: %d", c_loader, c_lsize); 
    LLDB_LOGF(log, "OFFSET_TO_USR: %d", offset_to_user); 
    ret = ParseUserData(data, &offset_to_user);

    ret = ParseLoaderData(data, &offset_to_loader);

    return true;

}
        
