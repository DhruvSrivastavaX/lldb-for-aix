add_lldb_library(lldbPluginObjectFileAIXdump PLUGIN
    ObjectFileAIXdump.cpp

  LINK_LIBS
    lldbCore
    lldbHost
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginProcessUtility
  LINK_COMPONENTS
    Support
  )
