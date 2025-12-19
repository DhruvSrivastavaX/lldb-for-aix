add_lldb_library(lldbPluginInstructionPPC PLUGIN
  EmulateInstructionPPC.cpp

  LINK_COMPONENTS
    Support
  LINK_LIBS
    lldbCore
    lldbInterpreter
    lldbSymbol
    lldbPluginProcessUtility
  )
