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

    struct Core64_AIX_Hdr {       /*                                                                      
         * First three elements are the same as the struct core_dump.           
         * If the field c_entries == 0, then the core file in question          
         * follows the new format.                                              
         */                                                                     
        char               c_signo;     /* signal number (cause of error) */    
        char               c_flag;      /* flag to describe core dump type */   
        short             c_entries;   /* number of core dump modules */           
                                                                                
        int                c_version;   /* core file format number */           
        // To be filled to completion
    };


}

#endif // AIXCORE_H
