add_lldb_library(lldbPluginProcessAIXCore PLUGIN
  ProcessAIXCore.cpp
  AIXCore.cpp

  LINK_LIBS
    lldbCore
    lldbTarget
    lldbPluginProcessUtility
  LINK_COMPONENTS
    BinaryFormat
    Support
  )
