#add_definitions("-D_ALL_SOURCE")

add_lldb_library(lldbPluginObjectFileAIXCore PLUGIN
    ObjectFileAIXCore.cpp

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
