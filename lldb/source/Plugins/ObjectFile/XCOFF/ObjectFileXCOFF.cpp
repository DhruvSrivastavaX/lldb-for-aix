//===-- ObjectFileXCOFF.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ObjectFileXCOFF.h"

#include <algorithm>
#include <cassert>
#include <unordered_map>

#include "lldb/Core/FileSpecList.h"
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

using namespace lldb;
using namespace llvm::XCOFF;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ObjectFileXCOFF)

char ObjectFileXCOFF::ID;

// Static methods.
void ObjectFileXCOFF::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                GetPluginDescriptionStatic(), CreateInstance,
                                CreateMemoryInstance, GetModuleSpecifications);
}

void ObjectFileXCOFF::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

ObjectFile *ObjectFileXCOFF::CreateInstance(const lldb::ModuleSP &module_sp,
                                          DataBufferSP data_sp,
                                          lldb::offset_t data_offset,
                                          const lldb_private::FileSpec *file,
                                          lldb::offset_t file_offset,
                                          lldb::offset_t length) {
  return nullptr;
}

ObjectFile *ObjectFileXCOFF::CreateMemoryInstance(
    const lldb::ModuleSP &module_sp, WritableDataBufferSP data_sp,
    const lldb::ProcessSP &process_sp, lldb::addr_t header_addr) {
  return nullptr;
}

size_t ObjectFileXCOFF::GetModuleSpecifications(
    const lldb_private::FileSpec &file, lldb::DataBufferSP &data_sp,
    lldb::offset_t data_offset, lldb::offset_t file_offset,
    lldb::offset_t length, lldb_private::ModuleSpecList &specs) {
  const size_t initial_count = specs.GetSize();

  if (ObjectFileXCOFF::MagicBytesMatch(data_sp, 0, data_sp->GetByteSize())) {
    ModuleSpec spec(file);
    spec.GetArchitecture().SetArchitecture(eArchTypeXCOFF, TCPU_COM, LLDB_INVALID_CPUTYPE, llvm::Triple::AIX);
    /*
    DataExtractor data;
    data.SetData(data_sp);
    llvm::MachO::mach_header header;
    if (ParseHeader(data, &data_offset, header)) {
      size_t header_and_load_cmds =
          header.sizeofcmds + MachHeaderSizeFromMagic(header.magic);
      if (header_and_load_cmds >= data_sp->GetByteSize()) {
        data_sp = MapFileData(file, header_and_load_cmds, file_offset);
        data.SetData(data_sp);
        data_offset = MachHeaderSizeFromMagic(header.magic);
      }
      if (data_sp) {
        ModuleSpec base_spec;
        base_spec.GetFileSpec() = file;
        base_spec.SetObjectOffset(file_offset);
        base_spec.SetObjectSize(length);
        GetAllArchSpecs(header, data, data_offset, base_spec, specs);
      }
    }
    */
  }
  return specs.GetSize() - initial_count;
}

static uint32_t XCOFFHeaderSizeFromMagic(uint32_t magic) {
  switch (magic) {
  case XCOFF32:
    return sizeof(struct llvm::object::XCOFFFileHeader32);

  case XCOFF64:
    return sizeof(struct llvm::object::XCOFFFileHeader64);
    break;

  default:
    break;
  }
  return 0;
}


bool ObjectFileXCOFF::MagicBytesMatch(DataBufferSP &data_sp,
                                    lldb::addr_t data_offset,
                                    lldb::addr_t data_length) {
  DataExtractor data; 
  data.SetData(data_sp, data_offset, data_length);
  lldb::offset_t offset = 0;
  uint16_t magic = data.GetU16(&offset);
  return XCOFFHeaderSizeFromMagic(magic) != 0;
}

bool ObjectFileXCOFF::ParseHeader() {
  return false;
}

bool ObjectFileXCOFF::SetLoadAddress(Target &target, lldb::addr_t value,
                                   bool value_is_offset) {
  return false;
}

ByteOrder ObjectFileXCOFF::GetByteOrder() const {
  return eByteOrderBig;
}

bool ObjectFileXCOFF::IsExecutable() const {
  return false;
}

uint32_t ObjectFileXCOFF::GetAddressByteSize() const {
  return 0;
}

AddressClass ObjectFileXCOFF::GetAddressClass(addr_t file_addr) {
  return AddressClass::eUnknown;
}

void ObjectFileXCOFF::ParseSymtab(Symtab &lldb_symtab) {
}

bool ObjectFileXCOFF::IsStripped() {
  return false;
}

void ObjectFileXCOFF::CreateSections(SectionList &unified_section_list) {
}

void ObjectFileXCOFF::Dump(Stream *s) {
}

ArchSpec ObjectFileXCOFF::GetArchitecture() {
  return ArchSpec();
}

UUID ObjectFileXCOFF::GetUUID() {
  return UUID();
}

llvm::Optional<FileSpec> ObjectFileXCOFF::GetDebugLink() {
  return llvm::None;
}

uint32_t ObjectFileXCOFF::GetDependentModules(FileSpecList &files) {
  return 0;
}

Address ObjectFileXCOFF::GetImageInfoAddress(Target *target) {
  return Address();
}

lldb_private::Address ObjectFileXCOFF::GetEntryPointAddress() {
  return lldb_private::Address();
}

lldb_private::Address ObjectFileXCOFF::GetBaseAddress() {
  return lldb_private::Address();
}

ObjectFile::Type ObjectFileXCOFF::CalculateType() {
  return eTypeUnknown;
}

ObjectFile::Strata ObjectFileXCOFF::CalculateStrata() {
  return eStrataUnknown;
}

size_t ObjectFileXCOFF::ReadSectionData(Section *section,
                       lldb::offset_t section_offset, void *dst,
                       size_t dst_len) {
  return 0;
}

size_t ObjectFileXCOFF::ReadSectionData(Section *section,
                                      DataExtractor &section_data) {
  return 0;
}

llvm::StringRef
ObjectFileXCOFF::StripLinkerSymbolAnnotations(llvm::StringRef symbol_name) const {
  return llvm::StringRef();
}

void ObjectFileXCOFF::RelocateSection(lldb_private::Section *section)
{
}

std::vector<ObjectFile::LoadableData>
ObjectFileXCOFF::GetLoadableData(Target &target) {
  std::vector<LoadableData> loadables;
  return loadables;
}

lldb::WritableDataBufferSP
ObjectFileXCOFF::MapFileDataWritable(const FileSpec &file, uint64_t Size,
                                   uint64_t Offset) {
  return FileSystem::Instance().CreateWritableDataBuffer(file.GetPath(), Size,
                                                         Offset);
}

ObjectFileXCOFF::ObjectFileXCOFF(const lldb::ModuleSP &module_sp,
                             DataBufferSP data_sp, lldb::offset_t data_offset,
                             const FileSpec *file, lldb::offset_t file_offset,
                             lldb::offset_t length)
    : ObjectFile(module_sp, file, file_offset, length, data_sp, data_offset) {
  if (file)
    m_file = *file;
}

ObjectFileXCOFF::ObjectFileXCOFF(const lldb::ModuleSP &module_sp,
                             DataBufferSP header_data_sp,
                             const lldb::ProcessSP &process_sp,
                             addr_t header_addr)
    : ObjectFile(module_sp, process_sp, header_addr, header_data_sp) {}

