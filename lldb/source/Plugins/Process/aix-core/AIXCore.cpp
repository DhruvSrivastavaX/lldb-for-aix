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

using namespace AIXCORE;
using namespace lldb;
using namespace lldb_private;

AIXCore64Header::AIXCore64Header() { memset(this, 0, sizeof(AIXCore64Header)); }

bool AIXCore64Header::Parse(lldb_private::DataExtractor &data,
                            lldb::offset_t *offset) {

    Log *log = GetLog(LLDBLog::Process);
    //if(data.GetU8(offset,  &c_signo, 1) == nullptr)
      //  return false;
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
    c_reserved[0] = data.GetU32(offset);
    c_reserved[1] = data.GetU32(offset);

    LLDB_LOGF(log, "c_fdsinfox %x, c_loader %x, c_lsize %x, c_n_thr %x, c_reserved0 %x, c_thr %x",
			c_fdsinfox, c_loader, c_lsize, c_n_thr, c_reserved0, c_thr);   
    LLDB_LOGF(log, "c_segsi %x, c_segregion %x, c_stack %x, c_stackorg %x, c_size %x, c_data %x, c_dataorg %x, c_datasize %x",c_segs, c_segregion, c_stack, c_stackorg, c_size, c_data, c_dataorg, 
c_datasize);
return true;

}
