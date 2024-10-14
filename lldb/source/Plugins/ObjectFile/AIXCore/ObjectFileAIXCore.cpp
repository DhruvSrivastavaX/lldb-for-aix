//===-- ObjectFileAIXCore.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ObjectFileAIXCore.h"

#include <algorithm>
#include <cassert>
#include <unordered_map>
#include <string.h>

#include "lldb/Utility/FileSpecList.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Progress.h"
#include "lldb/Core/Section.h"
#include "lldb/Host/FileSystem.h"
#include "lldb/Host/LZMA.h"
#include "lldb/Symbol/DWARFCallFrameInfo.h"
#include "lldb/Symbol/SymbolContext.h"
#include "lldb/Target/SectionLoadList.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/ArchSpec.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RangeMap.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/Stream.h"
#include "lldb/Utility/Timer.h"
#include "llvm/ADT/IntervalMap.h"
#include "llvm/ADT/PointerUnion.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/XCOFF.h"
#include "llvm/Object/Decompressor.h"
#include "llvm/Support/CRC.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Object/XCOFFObjectFile.h"
#include "Plugins/Process/aix-core/AIXCore.h"

using namespace llvm;
using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ObjectFileAIXCore)

bool m_is_core = false;

// FIXME: target 64bit at this moment.

// Static methods.
void ObjectFileAIXCore::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                GetPluginDescriptionStatic(), CreateInstance,
                                CreateMemoryInstance, GetModuleSpecifications);
}

void ObjectFileAIXCore::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

bool UGLY_FLAG_FOR_AIX __attribute__((weak)) = false;

ObjectFile *ObjectFileAIXCore::CreateInstance(const lldb::ModuleSP &module_sp,
                                          DataBufferSP data_sp,
                                          lldb::offset_t data_offset,
                                          const lldb_private::FileSpec *file,
                                          lldb::offset_t file_offset,
                                          lldb::offset_t length) {
  Log *log = GetLog(LLDBLog::Process);
  LLDB_LOGF(log, "CreateInstance AIXCore ++ 1.0 length %d", length);

  if(m_is_core)
  {

      LLDB_LOGF(log, "CreateInstance AIXCore ++ 1");  
      bool mapped_writable = false;
      if (!data_sp) {
          data_sp = MapFileDataWritable(*file, length, file_offset);
          if (!data_sp)
              return nullptr;
          data_offset = 0;
          mapped_writable = true;
      }

      assert(data_sp);

      //if (data_sp->GetByteSize() <= (llvm::ELF::EI_NIDENT + data_offset))
        //  return nullptr;
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 2 data_sp size %d", data_sp->GetByteSize());  

      const uint8_t *magic = data_sp->GetBytes() + data_offset;
      //if (!ELFHeader::MagicBytesMatch(magic))
        //  return nullptr;
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 3 %d", magic);  

      // Update the data to contain the entire file if it doesn't already
      if (data_sp->GetByteSize() < length) {
          data_sp = MapFileDataWritable(*file, length, file_offset);
          if (!data_sp)
              return nullptr;
          data_offset = 0;
          mapped_writable = true;
          magic = data_sp->GetBytes();
      }
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 4");  

      // If we didn't map the data as writable take ownership of the buffer.
      if (!mapped_writable) {
          data_sp = std::make_shared<DataBufferHeap>(data_sp->GetBytes(),
                  data_sp->GetByteSize());
          data_offset = 0;
          magic = data_sp->GetBytes();
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 5");  
      }
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 6");  

     // unsigned address_size = ELFHeader::AddressSizeInBytes(magic);
     // if (address_size == 4 || address_size == 8) {
          std::unique_ptr<ObjectFileAIXCore> objfile_up(new ObjectFileAIXCore(
                      module_sp, data_sp, data_offset, file, file_offset, length));
          ArchSpec spec = objfile_up->GetArchitecture();
          if (!spec)
              LLDB_LOGF(log, "CreateInstance AIXCore ++ spec");  
          if (objfile_up->SetModulesArchitecture(spec) == false)
              LLDB_LOGF(log, "CreateInstance AIXCore ++ arch");  
          if (spec /*&& objfile_up->SetModulesArchitecture(spec)*/)
              return objfile_up.release();
     // }
      LLDB_LOGF(log, "CreateInstance AIXCore ++ 7");  
      return nullptr;

  }
}

bool ObjectFileAIXCore::CreateCoreBinary()
{
  Log *log = GetLog(LLDBLog::Process);
  LLDB_LOGF(log, "CreateCoreBinary");  
  /*auto binary = llvm::object::XCOFFObjectFile::createObjectFile(llvm::MemoryBufferRef(
      toStringRef(m_data.GetData()), m_file.GetFilename().GetStringRef()),
    file_magic::aix_coredump_64);
  if (!binary) {
    LLDB_LOG_ERROR(log, binary.takeError(),
                   "Failed to create binary for file ({1}): {0}", m_file);
  LLDB_LOGF(log, "CreateCoreBinary ++1");  
    return false;
  }
  LLDB_LOGF(log, "CreateCoreBinary ++2");  
  m_binary =
      llvm::unique_dyn_cast<llvm::object::XCOFFObjectFile>(std::move(*binary));
  if (!m_binary)
    return false;

  LLDB_LOG(log, "this = {0}, module = {1} ({2}), file = {3}, binary = {4}",
           this, GetModule().get(), GetModule()->GetSpecificationDescription(),
           m_file.GetPath(), m_binary.get());*/
  return true;

} 

ObjectFile *ObjectFileAIXCore::CreateMemoryInstance(
    const lldb::ModuleSP &module_sp, WritableDataBufferSP data_sp,
    const lldb::ProcessSP &process_sp, lldb::addr_t header_addr) {
  return nullptr;
}

size_t ObjectFileAIXCore::GetModuleSpecifications(
    const lldb_private::FileSpec &file, lldb::DataBufferSP &data_sp,
    lldb::offset_t data_offset, lldb::offset_t file_offset,
    lldb::offset_t length, lldb_private::ModuleSpecList &specs) {
  const size_t initial_count = specs.GetSize();

  Log *log = GetLog(LLDBLog::Process);
    LLDB_LOGF(log, "GOT HERE!!! AIXCore GetModSpec %d", initial_count);
  if (ObjectFileAIXCore::MagicBytesMatch(data_sp, 0, data_sp->GetByteSize())) {
      /* Need new ArchType??? */
    ArchSpec arch_spec = ArchSpec(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE);
    ModuleSpec spec(file, arch_spec);
    spec.GetArchitecture().SetArchitecture(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE, llvm::Triple::AIX);
    specs.Append(spec);
  }
  return specs.GetSize() - initial_count;
}

enum CoreVersion : uint64_t {AIXCORE32 = 0xFEEDDB1, AIXCORE64 = 0xFEEDDB2};

static uint32_t AIXCoreHeaderSizeFromMagic(uint32_t magic) {
  Log *log = GetLog(LLDBLog::Process);
    LLDB_LOGF(log, "magic CORE %lx", magic);
    switch (magic) {

  case AIXCORE64:
      m_is_core = true;
    return sizeof(struct AIXCORE::AIXCore64Header);
    break;

    }
    return 0;
}

bool ObjectFileAIXCore::MagicBytesMatch(DataBufferSP &data_sp,
                                    lldb::addr_t data_offset,
                                    lldb::addr_t data_length) {
  lldb_private::DataExtractor data; 
  data.SetData(data_sp, data_offset, data_length);
  Log *log = GetLog(LLDBLog::Process);
    LLDB_LOGF(log, "MagicBytesMatch %d, %d", data_offset, data_length);
  lldb::offset_t offset = 0;
  offset += 4;
  uint32_t magic = data.GetU32(&offset);
  LLDB_LOGF(log, "MagicBytesMatch offset %d, len %d, magic:%lx", data_offset, data_length,
          magic);
  return AIXCoreHeaderSizeFromMagic(magic) != 0;
}

bool ObjectFileAIXCore::ParseHeader() {
#if 0
    ModuleSP module_sp(GetModule());
  if (module_sp) {
    std::lock_guard<std::recursive_mutex> guard(module_sp->GetMutex());
    m_sect_headers.clear();
    lldb::offset_t offset = 0;

    if (ParseXCOFFHeader(m_data, &offset, m_xcoff_header)) {
      m_data.SetAddressByteSize(GetAddressByteSize());
      if (m_xcoff_header.auxhdrsize > 0)
        ParseXCOFFOptionalHeader(m_data, &offset);
      ParseSectionHeaders(offset);
    }
    return true;
  }
#endif

  return false;
}

bool ObjectFileAIXCore::ParseAIXCoreHeader(lldb_private::DataExtractor &data,
                                       lldb::offset_t *offset_ptr
                                       ) {
  return false;
}


bool ObjectFileAIXCore::SetLoadAddress(Target &target, lldb::addr_t value,
                                   bool value_is_offset) {
  bool changed = false;
#if 0
  ModuleSP module_sp = GetModule();
  if (module_sp) {
    size_t num_loaded_sections = 0;
    SectionList *section_list = GetSectionList();
    if (section_list) {
      const size_t num_sections = section_list->GetSize();
      size_t sect_idx = 0;

      for (sect_idx = 0; sect_idx < num_sections; ++sect_idx) {
        // Iterate through the object file sections to find all of the sections
        // that have SHF_ALLOC in their flag bits.
        SectionSP section_sp(section_list->GetSectionAtIndex(sect_idx));
        if (section_sp && !section_sp->IsThreadSpecific()) {
          bool use_offset = false;
          if (strcmp(section_sp->GetName().AsCString(), ".text") == 0 ||
              strcmp(section_sp->GetName().AsCString(), ".data") == 0 ||
              strcmp(section_sp->GetName().AsCString(), ".bss") == 0)
            use_offset = true;

          if (target.GetSectionLoadList().SetSectionLoadAddress(
                  section_sp, (use_offset ?
                  (section_sp->GetFileOffset() + value) : (section_sp->GetFileAddress() + value))))
            ++num_loaded_sections;
        }
      }
      changed = num_loaded_sections > 0;
    }
  }
#endif
  return changed;
}

bool ObjectFileAIXCore::SetLoadAddressByType(Target &target, lldb::addr_t value,
                                   bool value_is_offset, int type_id) {
  bool changed = false;
#if 0
  ModuleSP module_sp = GetModule();
  if (module_sp) {
    size_t num_loaded_sections = 0;
    SectionList *section_list = GetSectionList();
    if (section_list) {
      const size_t num_sections = section_list->GetSize();
      size_t sect_idx = 0;

      for (sect_idx = 0; sect_idx < num_sections; ++sect_idx) {
        // Iterate through the object file sections to find all of the sections
        // that have SHF_ALLOC in their flag bits.
        SectionSP section_sp(section_list->GetSectionAtIndex(sect_idx));
        if (type_id == 1 && section_sp && strcmp(section_sp->GetName().AsCString(), ".text") == 0) {
          if (!section_sp->IsThreadSpecific()) {
            if (target.GetSectionLoadList().SetSectionLoadAddress(
                    section_sp, section_sp->GetFileOffset() + value))
              ++num_loaded_sections;
          }
        } else if (type_id == 2 && section_sp && strcmp(section_sp->GetName().AsCString(), ".data") == 0) {
          if (!section_sp->IsThreadSpecific()) {
            if (target.GetSectionLoadList().SetSectionLoadAddress(
                    section_sp, section_sp->GetFileAddress() + value))
              ++num_loaded_sections;
          }
        }
      }
      changed = num_loaded_sections > 0;
    }
  }
  return changed;
#endif
}

ByteOrder ObjectFileAIXCore::GetByteOrder() const {
  return eByteOrderBig;
}

bool ObjectFileAIXCore::IsExecutable() const {
  return true;
}

uint32_t ObjectFileAIXCore::GetAddressByteSize() const {
    return 8;
}

AddressClass ObjectFileAIXCore::GetAddressClass(addr_t file_addr) {
  return AddressClass::eUnknown;
}

lldb::SymbolType ObjectFileAIXCore::MapSymbolType(llvm::object::SymbolRef::Type sym_type) {
  if (sym_type == llvm::object::SymbolRef::ST_Function)
    return lldb::eSymbolTypeCode;
  else if (sym_type == llvm::object::SymbolRef::ST_Data)
    return lldb::eSymbolTypeData;
  return lldb::eSymbolTypeInvalid;
}

void ObjectFileAIXCore::ParseSymtab(Symtab &lldb_symtab) {
}

bool ObjectFileAIXCore::IsStripped() {
  return false;
}

void ObjectFileAIXCore::CreateSections(SectionList &unified_section_list) {
}

/*SectionType ObjectFileAIXCore::GetSectionType(llvm::StringRef sect_name,
                                             const section_header_t &sect) {
  return eSectionTypeOther;
}*/

void ObjectFileAIXCore::Dump(Stream *s) {
}

ArchSpec ObjectFileAIXCore::GetArchitecture() {
  ArchSpec arch_spec = ArchSpec(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE);
  return arch_spec;
}

UUID ObjectFileAIXCore::GetUUID() {
  return UUID();
}

uint32_t ObjectFileAIXCore::ParseDependentModules() {
    return 0;
}

uint32_t ObjectFileAIXCore::GetDependentModules(FileSpecList &files) {
  auto num_modules = ParseDependentModules();
  auto original_size = files.GetSize();

  for (unsigned i = 0; i < num_modules; ++i)
    files.AppendIfUnique(m_deps_filespec->GetFileSpecAtIndex(i));

  return files.GetSize() - original_size;
}

Address ObjectFileAIXCore::GetImageInfoAddress(Target *target) {
  return Address();
}

lldb_private::Address ObjectFileAIXCore::GetBaseAddress() {
  return lldb_private::Address();
}

ObjectFile::Type ObjectFileAIXCore::CalculateType() {
  return eTypeUnknown;
}

ObjectFile::Strata ObjectFileAIXCore::CalculateStrata() {
  return eStrataUnknown;
}

std::vector<ObjectFile::LoadableData>
ObjectFileAIXCore::GetLoadableData(Target &target) {
  std::vector<LoadableData> loadables;
  return loadables;
}

lldb::WritableDataBufferSP
ObjectFileAIXCore::MapFileDataWritable(const FileSpec &file, uint64_t Size,
                                   uint64_t Offset) {
  return FileSystem::Instance().CreateWritableDataBuffer(file.GetPath(), Size,
                                                         Offset);
}

ObjectFileAIXCore::ObjectFileAIXCore(const lldb::ModuleSP &module_sp,
                             DataBufferSP data_sp, lldb::offset_t data_offset,
                             const FileSpec *file, lldb::offset_t file_offset,
                             lldb::offset_t length)
    : ObjectFile(module_sp, file, file_offset, length, data_sp, data_offset)
      {
  if (file)
    m_file = *file;
}

ObjectFileAIXCore::ObjectFileAIXCore(const lldb::ModuleSP &module_sp,
                             DataBufferSP header_data_sp,
                             const lldb::ProcessSP &process_sp,
                             addr_t header_addr)
    : ObjectFile(module_sp, process_sp, header_addr, header_data_sp)
      {
}
