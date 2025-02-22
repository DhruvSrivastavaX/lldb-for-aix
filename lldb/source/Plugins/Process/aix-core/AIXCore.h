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

#include <sys/types.h>
#include <procinfo.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/cred.h>

namespace AIXCORE {


struct __context64 {
    // The data is arranged in order as filled by AIXCore.cpp in this coredump file
    // so we have to fetch in that exact order, refer there. 
    // But need to change
    // the context structure in order according to Infos_ppc64
        uint64_t           gpr[32];    /* 64-bit gprs */
        unsigned long           iar;            /* msr */
        unsigned long           msr;            /* iar */
        unsigned long           origr3;            /* iar */
        unsigned long           ctr;            /* CTR */
        unsigned long           lr;             /* LR */
        unsigned long           xer;            /* XER */
        unsigned long           cr;             /* CR */
        unsigned long           softe;             /* CR */
        unsigned long           trap;             /* CR */
        unsigned int            fpscr;          /* floating pt status reg */
        unsigned int            fpscrx;         /* software ext to fpscr */
        unsigned long           except[1];      /* exception address    */
        double                  fpr[32];    /* floating pt regs     */
        char                    fpeu;           /* floating pt ever used */
        char                    fpinfo;         /* floating pt info     */
        char                    fpscr24_31;     /* bits 24-31 of 64-bit FPSCR */
        char                    pad[1];
        int                     excp_type;      /* exception type       */
};

    struct ThreadContext64 {
        struct thrdentry64 threadEntry;
        struct __context64 context;
    };

    struct UserData {

        struct procentry64_53 process;
        unsigned long long reserved[16];
    };

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

        struct ThreadContext64 c_flt;

        struct UserData c_user;

        AIXCore64Header();

        bool ParseCoreHeader(lldb_private::DataExtractor &data,
                lldb::offset_t *offset);
        bool ParseThreadContext(lldb_private::DataExtractor &data,
                lldb::offset_t *offset);
        bool ParseUserData(lldb_private::DataExtractor &data,
                lldb::offset_t *offset);
        bool ParseRegisterContext(lldb_private::DataExtractor &data,
                lldb::offset_t *offset);
        bool ParseLoaderData(lldb_private::DataExtractor &data,
                lldb::offset_t *offset);

    };


}

#endif // AIXCORE_H
