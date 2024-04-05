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

using namespace llvm;
using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ObjectFileXCOFF)

char ObjectFileXCOFF::ID;

// FIXME: target 64bit at this moment.

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
  if (!data_sp) {
    data_sp = MapFileData(*file, length, file_offset);
    if (!data_sp)
      return nullptr;
    data_offset = 0;
  }

  if (!ObjectFileXCOFF::MagicBytesMatch(data_sp, data_offset, length))
    return nullptr;

  // Update the data to contain the entire file if it doesn't already
  if (data_sp->GetByteSize() < length) {
    data_sp = MapFileData(*file, length, file_offset);
    if (!data_sp)
      return nullptr;
    data_offset = 0;
  }
  auto objfile_up = std::make_unique<ObjectFileXCOFF>(
      module_sp, data_sp, data_offset, file, file_offset, length);
  if (!objfile_up || !objfile_up->ParseHeader())
    return nullptr;

  // Cache xcoff binary.
  if (!objfile_up->CreateBinary())
    return nullptr;
  return objfile_up.release();
}

bool ObjectFileXCOFF::CreateBinary() {
  if (m_binary)
    return true;

  Log *log = GetLog(LLDBLog::Object);

  auto binary = llvm::object::createBinary(llvm::MemoryBufferRef(
      toStringRef(m_data.GetData()), m_file.GetFilename().GetStringRef()));
  if (!binary) {
    LLDB_LOG_ERROR(log, binary.takeError(),
                   "Failed to create binary for file ({1}): {0}", m_file);
    return false;
  }

  // Make sure we only handle COFF format.
  m_binary =
      llvm::unique_dyn_cast<llvm::object::XCOFFObjectFile>(std::move(*binary));
  if (!m_binary)
    return false;

  LLDB_LOG(log, "this = {0}, module = {1} ({2}), file = {3}, binary = {4}",
           this, GetModule().get(), GetModule()->GetSpecificationDescription(),
           m_file.GetPath(), m_binary.get());
  return true;
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
    ArchSpec arch_spec = ArchSpec(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE);
    ModuleSpec spec(file, arch_spec);
    spec.GetArchitecture().SetArchitecture(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE, llvm::Triple::AIX);
    specs.Append(spec);
  }
  return specs.GetSize() - initial_count;
}

static uint32_t XCOFFHeaderSizeFromMagic(uint32_t magic) {
  switch (magic) {
  case XCOFF::XCOFF32:
    return sizeof(struct llvm::object::XCOFFFileHeader32);

  case XCOFF::XCOFF64:
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
  lldb_private::DataExtractor data; 
  data.SetData(data_sp, data_offset, data_length);
  lldb::offset_t offset = 0;
  uint16_t magic = data.GetU16(&offset);
  return XCOFFHeaderSizeFromMagic(magic) != 0;
}

bool ObjectFileXCOFF::ParseHeader() {
  ModuleSP module_sp(GetModule());
  if (module_sp) {
    std::lock_guard<std::recursive_mutex> guard(module_sp->GetMutex());
    m_sect_headers.clear();
    lldb::offset_t offset = 0;

    if (ParseXCOFFHeader(m_data, &offset, m_xcoff_header)) {
      m_data.SetAddressByteSize(GetAddressByteSize());
      if (m_xcoff_header.auxhdrsize > 0)
        ParseXCOFFOptionalHeader(&offset);
      ParseSectionHeaders(offset);
    }
    return true;
  }

  return false;
}

bool ObjectFileXCOFF::ParseXCOFFHeader(lldb_private::DataExtractor &data,
                                       lldb::offset_t *offset_ptr,
                                       xcoff_header_t &xcoff_header) {
  //FIXME: data.ValidOffsetForDataOfSize
  xcoff_header.magic = data.GetU16(offset_ptr);
  xcoff_header.nsects = data.GetU16(offset_ptr);
  xcoff_header.modtime = data.GetU32(offset_ptr);
  xcoff_header.symoff = data.GetU64(offset_ptr);
  xcoff_header.auxhdrsize = data.GetU16(offset_ptr);
  xcoff_header.flags = data.GetU16(offset_ptr);
  xcoff_header.nsyms = data.GetU32(offset_ptr);
  return true;
}

bool ObjectFileXCOFF::ParseXCOFFOptionalHeader(lldb::offset_t *offset_ptr) {
  //FIXME
  *offset_ptr += m_xcoff_header.auxhdrsize;
  return false;
}

bool ObjectFileXCOFF::ParseSectionHeaders(
    uint32_t section_header_data_offset) {
  const uint32_t nsects = m_xcoff_header.nsects;
  m_sect_headers.clear();

  if (nsects > 0) {
    const size_t section_header_byte_size = nsects * m_binary->getSectionHeaderSize();
    lldb_private::DataExtractor section_header_data =
        ReadImageData(section_header_data_offset, section_header_byte_size);

    lldb::offset_t offset = 0;
    //FIXME: section_header_data.ValidOffsetForDataOfSize
    m_sect_headers.resize(nsects);

    for (uint32_t idx = 0; idx < nsects; ++idx) {
      const void *name_data = section_header_data.GetData(&offset, 8);
      if (name_data) {
        memcpy(m_sect_headers[idx].name, name_data, 8);
        m_sect_headers[idx].phyaddr = section_header_data.GetU64(&offset);
        m_sect_headers[idx].vmaddr = section_header_data.GetU64(&offset);
        m_sect_headers[idx].size = section_header_data.GetU64(&offset);
        m_sect_headers[idx].offset = section_header_data.GetU64(&offset);
        m_sect_headers[idx].reloff = section_header_data.GetU64(&offset);
        m_sect_headers[idx].lineoff = section_header_data.GetU64(&offset);
        m_sect_headers[idx].nreloc = section_header_data.GetU32(&offset);
        m_sect_headers[idx].nline = section_header_data.GetU32(&offset);
        m_sect_headers[idx].flags = section_header_data.GetU32(&offset);
        offset += 4;
      } else {
        offset += (m_binary->getSectionHeaderSize() - 8);
      }
    }
  }

  return !m_sect_headers.empty();
}

lldb_private::DataExtractor ObjectFileXCOFF::ReadImageData(uint32_t offset, size_t size) {
  if (!size)
    return {};

  if (m_data.ValidOffsetForDataOfSize(offset, size))
    return lldb_private::DataExtractor(m_data, offset, size);

  assert(0);
  ProcessSP process_sp(m_process_wp.lock());
  lldb_private::DataExtractor data;
  if (process_sp) {
    auto data_up = std::make_unique<DataBufferHeap>(size, 0);
    Status readmem_error;
    size_t bytes_read =
        process_sp->ReadMemory(offset, data_up->GetBytes(),
                               data_up->GetByteSize(), readmem_error);
    if (bytes_read == size) {
      DataBufferSP buffer_sp(data_up.release());
      data.SetData(buffer_sp, 0, buffer_sp->GetByteSize());
    }
  }
  return data;
}

bool ObjectFileXCOFF::SetLoadAddress(Target &target, lldb::addr_t value,
                                   bool value_is_offset) {
  return false;
}

ByteOrder ObjectFileXCOFF::GetByteOrder() const {
  return eByteOrderBig;
}

bool ObjectFileXCOFF::IsExecutable() const {
  return true;
}

uint32_t ObjectFileXCOFF::GetAddressByteSize() const {
  if (m_xcoff_header.magic == XCOFF::XCOFF64)
    return 8;
  else if (m_xcoff_header.magic == XCOFF::XCOFF32)
    return 4;
  return 4;
}

AddressClass ObjectFileXCOFF::GetAddressClass(addr_t file_addr) {
  return AddressClass::eUnknown;
}

lldb::SymbolType ObjectFileXCOFF::MapSymbolType(llvm::object::SymbolRef::Type sym_type) {
  if (sym_type == llvm::object::SymbolRef::ST_Function)
    return lldb::eSymbolTypeCode;
  else if (sym_type == llvm::object::SymbolRef::ST_Data)
    return lldb::eSymbolTypeData;
  return lldb::eSymbolTypeInvalid;
}

void ObjectFileXCOFF::ParseSymtab(Symtab &lldb_symtab) {
  SectionList *sect_list = GetSectionList();
  const uint32_t num_syms = m_xcoff_header.nsyms;
  if (num_syms > 0 && m_xcoff_header.symoff > 0) {
    const uint32_t symbol_size = XCOFF::SymbolTableEntrySize;
    const size_t symbol_data_size = num_syms * symbol_size;
    lldb_private::DataExtractor symtab_data =
        ReadImageData(m_xcoff_header.symoff, symbol_data_size);

    lldb::offset_t offset = 0;
    std::string symbol_name;
    Symbol *symbols = lldb_symtab.Resize(num_syms);
    llvm::object::symbol_iterator SI = m_binary->symbol_begin();
    for (uint32_t i = 0; i < num_syms; ++i, ++SI) {
      xcoff_symbol_t symbol;
      const uint32_t symbol_offset = offset;
      symbol.value = symtab_data.GetU64(&offset);
      symbol.offset = symtab_data.GetU32(&offset);
      Expected<StringRef> symbol_name_or_err = m_binary->getStringTableEntry(symbol.offset);
      if (!symbol_name_or_err) {
        Error err = symbol_name_or_err.takeError();
        return;
      }
      StringRef symbol_name_str = symbol_name_or_err.get();
      symbol_name.assign(symbol_name_str.data());
      symbol.sect = symtab_data.GetU16(&offset);
      symbol.type = symtab_data.GetU16(&offset);
      symbol.storage = symtab_data.GetU8(&offset);
      symbol.naux = symtab_data.GetU8(&offset);
      symbols[i].GetMangled().SetValue(ConstString(symbol_name.c_str()));
      if ((int16_t)symbol.sect >= 1) {
        if (symbol.storage == XCOFF::C_EXT) {
          Address symbol_addr(symbol.value, sect_list);
          symbols[i].GetAddressRef() = symbol_addr;
        }
        Expected<llvm::object::SymbolRef::Type> sym_type_or_err = SI->getType();
        if (!sym_type_or_err) {
          Error err = sym_type_or_err.takeError();
          return;
        }
        symbols[i].SetType(MapSymbolType(sym_type_or_err.get()));
      }

      if (symbol.naux > 0) {
        i += symbol.naux;
        offset += symbol.naux * symbol_size;
      }
    }
  }
}

bool ObjectFileXCOFF::IsStripped() {
  return false;
}

void ObjectFileXCOFF::CreateSections(SectionList &unified_section_list) {
  if (m_sections_up)
    return;
  m_sections_up = std::make_unique<SectionList>();
  ModuleSP module_sp(GetModule());
  if (module_sp) {
    std::lock_guard<std::recursive_mutex> guard(module_sp->GetMutex());

#if 0
    lldb::offset_t offset = 0;
    const uint32_t addr_byte_size = GetAddressByteSize();
    SectionSP header_sp = std::make_shared<Section>(
        module_sp, this, ~user_id_t(0), ConstString("XCOFF header"),
        eSectionTypeOther, m_data.GetMaxU64(&offset, addr_byte_size),
        sizeof(*m_binary->fileHeader64()), 0, sizeof(*m_binary->fileHeader64()),
        0, 0);
    header_sp->SetPermissions(ePermissionsReadable);
    m_sections_up->AddSection(header_sp);
    unified_section_list.AddSection(header_sp);
#endif

    const uint32_t nsects = m_sect_headers.size();
    ModuleSP module_sp(GetModule());
    for (uint32_t idx = 0; idx < nsects; ++idx) {
      llvm::StringRef sect_name = GetSectionName(m_sect_headers[idx]);
      ConstString const_sect_name(sect_name);
      SectionType section_type = GetSectionType(sect_name, m_sect_headers[idx]);

      SectionSP section_sp(new Section(
          module_sp,       // Module to which this section belongs
          this,            // Object file to which this section belongs
          idx + 1,         // Section ID is the 1 based section index.
          const_sect_name, // Name of this section
          section_type,
          m_sect_headers[idx].vmaddr, // File VM address == addresses as
                                          // they are found in the object file
          m_sect_headers[idx].size,     // VM size in bytes of this section
          m_sect_headers[idx].offset, // Offset to the data for this section in the file
          m_sect_headers[idx].size, // Size in bytes of this section as found in the file
          0, // FIXME: alignment
          m_sect_headers[idx].flags));      // Flags for this section

      // FIXME
      uint32_t permissions = 0;
      permissions |= ePermissionsReadable;
      if (m_sect_headers[idx].flags & (XCOFF::STYP_DATA | XCOFF::STYP_BSS))
        permissions |= ePermissionsWritable;
      if (m_sect_headers[idx].flags & XCOFF::STYP_TEXT)
        permissions |= ePermissionsExecutable;
      section_sp->SetPermissions(permissions);

      m_sections_up->AddSection(section_sp);
      unified_section_list.AddSection(section_sp);
    }
  }
}

llvm::StringRef ObjectFileXCOFF::GetSectionName(const section_header_t &sect) {
  llvm::StringRef hdr_name(sect.name, llvm::array_lengthof(sect.name));
  hdr_name = hdr_name.split('\0').first;
  if (hdr_name.consume_front("/")) {
    lldb::offset_t stroff;
    if (!to_integer(hdr_name, stroff, 10))
      return "";
    lldb::offset_t string_file_offset =
        m_xcoff_header.symoff + (m_xcoff_header.nsyms * static_cast<lldb::offset_t>(XCOFF::SymbolTableEntrySize)) + stroff;
    if (const char *name = m_data.GetCStr(&string_file_offset))
      return name;
    return "";
  }
  return hdr_name;
}

SectionType ObjectFileXCOFF::GetSectionType(llvm::StringRef sect_name,
                                             const section_header_t &sect) {
  if (sect.flags & XCOFF::STYP_TEXT)
    return eSectionTypeCode;
  if (sect.flags & XCOFF::STYP_DATA)
    return eSectionTypeData;
  if (sect.flags & XCOFF::STYP_BSS)
    return eSectionTypeZeroFill;

  return eSectionTypeOther;
}

void ObjectFileXCOFF::Dump(Stream *s) {
}

ArchSpec ObjectFileXCOFF::GetArchitecture() {
  ArchSpec arch_spec = ArchSpec(eArchTypeXCOFF, XCOFF::TCPU_PPC64, LLDB_INVALID_CPUTYPE);
  return arch_spec;
}

UUID ObjectFileXCOFF::GetUUID() {
  return UUID();
}

llvm::Optional<FileSpec> ObjectFileXCOFF::GetDebugLink() {
  return llvm::None;
}

uint32_t ObjectFileXCOFF::ParseDependentModules() {
  ModuleSP module_sp(GetModule());
  if (!module_sp)
    return 0;

  std::lock_guard<std::recursive_mutex> guard(module_sp->GetMutex());
  if (m_deps_filespec)
    return m_deps_filespec->GetSize();

  // Cache coff binary if it is not done yet.
  if (!CreateBinary())
    return 0;

  Log *log = GetLog(LLDBLog::Object);
  LLDB_LOG(log, "this = {0}, module = {1} ({2}), file = {3}, binary = {4}",
           this, GetModule().get(), GetModule()->GetSpecificationDescription(),
           m_file.GetPath(), m_binary.get());

  m_deps_filespec = FileSpecList();

  auto ImportFilesOrError = m_binary->getImportFileTable();
  if (!ImportFilesOrError) {
    Error err = ImportFilesOrError.takeError();
    return 0;
  }

  StringRef ImportFileTable = ImportFilesOrError.get();
  const char *CurrentStr = ImportFileTable.data();
  const char *TableEnd = ImportFileTable.end();

  for (size_t StrIndex = 0; CurrentStr < TableEnd;
       ++StrIndex, CurrentStr += strlen(CurrentStr) + 1) {
    if (StrIndex >= 3 && StrIndex % 3 == 1) {
      llvm::StringRef dll_name(CurrentStr);

      // At this moment we only have the base name of the DLL. The full path can
      // only be seen after the dynamic loading.  Our best guess is Try to get it
      // with the help of the object file's directory.
      llvm::SmallString<128> dll_fullpath;
      FileSpec dll_specs(dll_name);
      dll_specs.GetDirectory().SetString(m_file.GetDirectory().GetCString());

      if (!llvm::sys::fs::real_path(dll_specs.GetPath(), dll_fullpath))
        m_deps_filespec->EmplaceBack(dll_fullpath);
      else {
        // Known DLLs or DLL not found in the object file directory.
        m_deps_filespec->EmplaceBack(dll_name);
      }
    }
  }
  return m_deps_filespec->GetSize();
}

uint32_t ObjectFileXCOFF::GetDependentModules(FileSpecList &files) {
  auto num_modules = ParseDependentModules();
  auto original_size = files.GetSize();

  for (unsigned i = 0; i < num_modules; ++i)
    files.AppendIfUnique(m_deps_filespec->GetFileSpecAtIndex(i));

  return files.GetSize() - original_size;
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
  if (m_xcoff_header.flags & XCOFF::F_EXEC)
    return eTypeExecutable;
  else if (m_xcoff_header.flags & XCOFF::F_SHROBJ)
    return eTypeSharedLibrary;
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
                                      lldb_private::DataExtractor &section_data) {
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
    : ObjectFile(module_sp, file, file_offset, length, data_sp, data_offset),
      m_xcoff_header(), m_sect_headers(), m_deps_filespec() {
  ::memset(&m_xcoff_header, 0, sizeof(m_xcoff_header));
  if (file)
    m_file = *file;
}

ObjectFileXCOFF::ObjectFileXCOFF(const lldb::ModuleSP &module_sp,
                             DataBufferSP header_data_sp,
                             const lldb::ProcessSP &process_sp,
                             addr_t header_addr)
    : ObjectFile(module_sp, process_sp, header_addr, header_data_sp),
      m_xcoff_header(), m_sect_headers(), m_deps_filespec() {
  ::memset(&m_xcoff_header, 0, sizeof(m_xcoff_header));
}
