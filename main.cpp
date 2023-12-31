#include <string>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include "Process/Process.hpp"
#include "PEParser/PEParser.hpp"
#include <filesystem>
#include "Injector/Injector.hpp"

int main(int argc, const char* argv[])
{
	bool should_disable_minhook = false;
	std::string dll_path{};
	std::ifstream dll{ dll_path, std::ios::binary};
	while (!dll.is_open())
	{
		std::cout << "Dll path: ";
		std::getline(std::cin, dll_path);
		if (!dll_path.empty())
			dll.open(dll_path, std::ios::binary);
		if (!dll.is_open())
			std::cerr << "[-] Failed to open dll file\n";
	}

	Process process{};
	while (!process)
	{
		std::string window_name{};
		std::cout << "Window name: ";
		std::getline(std::cin, window_name);
		process = window_name.c_str();
		if (!process)
			std::cerr << "[-] Failed to open target process\n";
	}


	while (true)
	{
		std::string yes_no{};
		std::cout << "Disable minhook ? y/n: ";
		std::getline(std::cin, yes_no);
		if (yes_no == "y")
		{
			should_disable_minhook = true;
			break;
		}
		if (yes_no == "n")
		{
			should_disable_minhook = false;
			break;
		}
		std::cerr << "[-] Invalid answer, enter y or n\n";
	}

	if (should_disable_minhook)
		process.disableHooks();

	Injector injector(process);
	injector.inject(std::filesystem::absolute(dll_path).string());

	return 0;

	/* Manual map not working
	dll.seekg(0, std::ios::end);
	size_t dll_size = dll.tellg();
	dll.seekg(0, std::ios::beg);
	std::unique_ptr<uint8_t[]> dll_copy = std::make_unique<uint8_t[]>(dll_size);
	dll.read((char*)dll_copy.get(), dll_size);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_copy.get();
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(dll_copy.get() + dos_header->e_lfanew);
	uint32_t image_size_memory = nt_header->OptionalHeader.SizeOfImage;

	uint8_t* allocated_dll = process.allocate_memory(nullptr, image_size_memory, PAGE_READONLY);
	std::cout << "preferred base: " << (void*)nt_header->OptionalHeader.ImageBase << '\n';
	std::cout << "new base: " << (void*)allocated_dll << '\n';
	std::unique_ptr<uint8_t[]> zero = std::make_unique<uint8_t[]>(image_size_memory);
	memset(zero.get(), 0, image_size_memory);
	process.write_memory<uint8_t>(allocated_dll, zero.get(), image_size_memory);

	//relocations
	uint8_t* preferred_image_base = (uint8_t*)nt_header->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY reloc_data_dir = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uint32_t reloc_data_file_addr = virtual_to_file_address(reloc_data_dir->VirtualAddress, nt_header);
	PIMAGE_BASE_RELOCATION base_start = (PIMAGE_BASE_RELOCATION)(dll_copy.get() + reloc_data_file_addr);
	PIMAGE_BASE_RELOCATION base_end = (PIMAGE_BASE_RELOCATION)((uint8_t*)base_start + reloc_data_dir->Size);
	while (base_start < base_end)
	{
		uint8_t* block_end = (uint8_t*)base_start + base_start->SizeOfBlock;
		uint32_t block_file_offset = virtual_to_file_address(base_start->VirtualAddress, nt_header);

		for (PIMAGE_RELOCATION_ENTRY entry = (PIMAGE_RELOCATION_ENTRY)((uint8_t*)base_start + sizeof(IMAGE_BASE_RELOCATION));
			entry < (PIMAGE_RELOCATION_ENTRY)block_end;
			++entry
			)
		{
			if ((entry->Type & IMAGE_REL_BASED_DIR64) == 0)
			{
				continue; //TODO handle other relocs
			}
			uint32_t to_reloc_file_offset = block_file_offset + entry->Offset;
			uint8_t** p_to_reloc = (uint8_t**)(dll_copy.get() + to_reloc_file_offset);
			std::cout << "to reloc: " << (void*)*p_to_reloc << '\n';
			uint8_t* relocated = *p_to_reloc - preferred_image_base + allocated_dll;
			*p_to_reloc = relocated;
			std::cout << "reocated: " << (void*)*p_to_reloc << '\n';
		}

		base_start = (PIMAGE_BASE_RELOCATION)block_end;
	}


	//fix imports
	PIMAGE_DATA_DIRECTORY import_dir = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	uint32_t import_descriptors_file_offset = virtual_to_file_address(import_dir->VirtualAddress, nt_header);
	uint8_t* import_descriptors_start = dll_copy.get() + import_descriptors_file_offset;
	for (PIMAGE_IMPORT_DESCRIPTOR import_descriptors = (PIMAGE_IMPORT_DESCRIPTOR)import_descriptors_start;
		import_descriptors < (PIMAGE_IMPORT_DESCRIPTOR)(import_descriptors_start + import_dir->Size);
		++import_descriptors)
	{
		if (!import_descriptors->Characteristics) break;
		uint32_t dll_name_file_offset = virtual_to_file_address(import_descriptors->Name, nt_header);
		const char* dll_name = (const char*)dll_copy.get() + dll_name_file_offset;
		std::cout << dll_name << '\n';

		uint32_t import_table_file_offset = virtual_to_file_address(import_descriptors->OriginalFirstThunk, nt_header);
		uint32_t new_import_table_file_offset = virtual_to_file_address(import_descriptors->FirstThunk, nt_header);
		for (PIMAGE_THUNK_DATA o_thunk = (PIMAGE_THUNK_DATA)(dll_copy.get() + import_table_file_offset),
			n_thunk = (PIMAGE_THUNK_DATA)(dll_copy.get() + new_import_table_file_offset);
			o_thunk->u1.AddressOfData != 0;
			++o_thunk, ++n_thunk
			)
		{ //TODO resolve ordinal import
			if ((o_thunk->u1.AddressOfData & (1ULL << 63)) != 0)
			{
				std::cout << "ordinal import" << '\n';
				return -1;
			}
			uint32_t import_name_offset = virtual_to_file_address(o_thunk->u1.AddressOfData, nt_header);
			PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(dll_copy.get() + import_name_offset);
			uint8_t* import = process.get_proc_address(dll_name, import_by_name->Name);
			std::cout << "   " << import_by_name->Name << '\n';
			n_thunk->u1.Function = (uint64_t)import;
			if (!import)
				std::cout << "failed" << '\n';
		}
	}

	process.write_memory<uint8_t>(allocated_dll, dll_copy.get(), nt_header->OptionalHeader.SizeOfHeaders);

	for (PIMAGE_SECTION_HEADER section : get_section_headers(nt_header))
	{
		process.write_memory<uint8_t>(allocated_dll + section->VirtualAddress, dll_copy.get() + section->PointerToRawData, section->SizeOfRawData);
		DWORD charact = section->Characteristics;
		DWORD protection = PAGE_EXECUTE_READWRITE;
		if ((charact & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) != 0)
			protection = PAGE_EXECUTE_READWRITE;
		else if ((charact & IMAGE_SCN_MEM_EXECUTE) != 0)
			protection = PAGE_EXECUTE_READ;
		else if ((charact & IMAGE_SCN_MEM_WRITE) != 0)
			protection = PAGE_READWRITE;
		process.set_protection(allocated_dll + section->VirtualAddress, section->Misc.VirtualSize, protection);
	}

	uint8_t* entry_point = allocated_dll + nt_header->OptionalHeader.AddressOfEntryPoint;
	std::cout << "entry point: " << (void*)entry_point << '\n';

	return 0;

	Process::RemoteThreadData<3> td( {allocated_dll, (uint8_t*)DLL_THREAD_ATTACH, nullptr} );
	process.create_remote_thread<3>(entry_point, td);

	return 0;
	*/
}