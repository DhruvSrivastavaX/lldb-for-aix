//==AIXCore.h 
//
// ADD Prologue text
//
//

#ifndef AIXCORE_H
#define AIXCORE_H

#include "llvm/ADT/StringRef.h"
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace AIXCORE {

    struct AIXCore64Header {

        int8_t   c_signo;     /* signal number (cause of error) */    
        int8_t   c_flag;      /* flag to describe core dump type */   
        uint16_t c_entries;   /* number of core dump modules */           
        uint32_t c_version;   /* core file format number */           
        uint64_t c_fdsinfox;  /* offset to fd region in file */

        uint64_t c_loader;    /* offset to loader region in file */
        uint64_t c_lsize;     /* size of loader region */

        uint32_t c_n_thr;     /* number of elements in thread table */
        uint32_t c_reserved0; /* Padding                            */
        uint64_t c_thr;       /* offset to thread context table */

        uint64_t c_segs;      /* n of elements in segregion */
        uint64_t c_segregion; /* offset to start of segregion table */

        uint64_t c_stack;     /* offset of user stack in file */
        uint64_t c_stackorg;  /* base address of user stack region */
        uint64_t c_size;      /* size of user stack region */

        uint64_t c_data;      /* offset to user data region */
        uint64_t c_dataorg;   /* base address of user data region */
        uint64_t c_datasize;  /* size of user data region */
        uint64_t c_sdorg;     /* base address of sdata region */
        uint64_t c_sdsize;    /* size of sdata region */

        uint64_t c_vmregions; /* number of anonymously mapped areas */
        uint64_t c_vmm;       /* offset to start of vm_infox table */

        int32_t  c_impl;      /* processor implementation */
        uint32_t c_n_extctx;  /* n of elements in extended ctx table*/
        uint64_t c_cprs;      /* Checkpoint/Restart offset */
        uint64_t c_extctx;    /* extended context offset */
        uint64_t c_ukeyctx;   /* Offset to user-key exception data */
        uint64_t c_loader2;   /* offset to the loader region in file
                                 when a process uses TLS data */
        uint64_t c_lsize2;    /* size of the above loader region */
        uint64_t c_extproc;   /* Extended procentry64 information */
        uint64_t c_reserved[2];

        //To add structs

        AIXCore64Header();

        bool Parse(lldb_private::DataExtractor &data,
                lldb::offset_t *offset); 

    };


}

#endif // AIXCORE_H
