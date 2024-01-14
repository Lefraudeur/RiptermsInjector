#include "Injector.hpp"
#include "../PEParser/PEParser.hpp"
#include <thread>

Injector::Injector(Process& process) :
	process(process)
{
}

void Injector::inject(uint8_t dll_bytes[], size_t dll_size)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(dll_bytes + dos_header->e_lfanew);
	uint32_t image_size_memory = nt_header->OptionalHeader.SizeOfImage;

	Process::RemoteMemoryHolder<uint8_t> remote_image = process.remote_allocate<uint8_t>(image_size_memory, PAGE_EXECUTE_READWRITE);
	relocate(dll_bytes, dll_size, remote_image.get());

	process.write_memory<uint8_t>(remote_image.get(), dll_bytes, nt_header->OptionalHeader.SizeOfHeaders);
	process.set_protection(remote_image.get(), nt_header->OptionalHeader.SizeOfHeaders, PAGE_READONLY);
	for (PIMAGE_SECTION_HEADER section : get_section_headers(nt_header))
	{
		process.write_memory<uint8_t>(remote_image.get() + section->VirtualAddress, dll_bytes + section->PointerToRawData, section->SizeOfRawData);
		if (section->Misc.VirtualSize > section->SizeOfRawData)
		{
			int zero_count = section->Misc.VirtualSize - section->SizeOfRawData;
			std::unique_ptr<uint8_t[]> zeros = std::make_unique<uint8_t[]>(section->Misc.VirtualSize - section->SizeOfRawData);
			process.write_memory<uint8_t>(remote_image.get() + section->VirtualAddress + section->SizeOfRawData, zeros.get(), zero_count);
		}
	}

	{ //write shellcode that will resolve imports and call entry_point
		HeapAlloc_t* p_HeapAlloc_IAT = get_HeapAlloc_IAT();
		HeapAlloc_t original_HeapAlloc_address = process.read_memory<HeapAlloc_t>(p_HeapAlloc_IAT);
		LoadLibraryA_t LoadLibraryA_address = (LoadLibraryA_t)process.get_proc_address("Kernel32.dll", "LoadLibraryA");
		GetProcAddress_t GetProcAddress_address = (GetProcAddress_t)process.get_proc_address("Kernel32.dll", "GetProcAddress");
		VirtualProtect_t VirtualProtect_address = (VirtualProtect_t)process.get_proc_address("Kernel32.dll", "VirtualProtect");
		RtlAddFunctionTable_t RtlAddFunctionTable_address = (RtlAddFunctionTable_t)process.get_proc_address("Kernel32.dll", "RtlAddFunctionTable");

		/*
			mov rax, [rip + data + 8] # p_heapalloc_IAT
			mov r9, [rip + data]
			mov [rax], r9 # *p_heapalloc_IAT = original_HeapAlloc_address
			push rcx
			push rdx
			push r8 # 3 pushes, aligns the stack
			sub rsp, 32 # shadow space

			lea rcx, [rip + data] # HookData* data
			call [rip + data + 48] # set_imports

			add rsp, 32
			pop r8
			pop rdx
			pop rcx
			jmp [rip + data]
			data:
		*/
		uint8_t assembly[] =
		{ 
			0x48, 0x8B, 0x05, 0x35, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x0D, 0x26, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x08, 0x51, 0x52, 0x41, 0x50, 0x48, 0x83, 
			0xEC, 0x20, 0x48, 0x8D, 0x0D, 0x14, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x3E, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x58, 0x5A, 0x59, 
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 
		};

		Process::RemoteMemoryHolder<uint8_t> remote_set_imports = process.remote_allocate<uint8_t>(0x200, PAGE_EXECUTE_READ);
		remote_set_imports.write((uint8_t*)set_imports, 0x200); //we don't know the size of the function (around 0x1C1)

		HookData data
		{
			original_HeapAlloc_address,
			p_HeapAlloc_IAT,
			remote_image.get(),
			LoadLibraryA_address,
			GetProcAddress_address,
			VirtualProtect_address,
			(void(*)(HookData* data))remote_set_imports.get(),
			RtlAddFunctionTable_address
		};

		Process::RemoteMemoryHolder<uint8_t> remote_data = process.remote_allocate<uint8_t>(sizeof(assembly) + sizeof(data), PAGE_EXECUTE_READ);
		process.write_memory<uint8_t>(remote_data.get(), assembly, sizeof(assembly));
		process.write_memory<HookData>((HookData*)(remote_data.get() + sizeof(assembly)), data);

		process.set_protection((uint8_t*)p_HeapAlloc_IAT, 8, PAGE_READWRITE);
		process.write_memory<HeapAlloc_t>(p_HeapAlloc_IAT, (HeapAlloc_t)remote_data.get());

		std::cout << "If the dll isn't injected yet, return to the game's window\n"
			"Press enter to deallocate injected dll, make sure the dll has done executing first !\n";
		std::cin.ignore();
	}
}

Injector::HeapAlloc_t* Injector::get_HeapAlloc_IAT()
{
	HMODULE process_module = process.get_module_handle("msvcrt.dll");
	MODULEINFO info = process.get_module_info(process_module);

	std::unique_ptr<uint8_t[]> module_copy = process.read_memory<uint8_t>((uint8_t*)process_module, info.SizeOfImage);
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_copy.get();
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(module_copy.get() + dos_header->e_lfanew);

	PIMAGE_DATA_DIRECTORY import_dir = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	uint8_t* import_descriptors_start = module_copy.get() + import_dir->VirtualAddress;
	for (PIMAGE_IMPORT_DESCRIPTOR import_descriptors = (PIMAGE_IMPORT_DESCRIPTOR)import_descriptors_start;
		import_descriptors < (PIMAGE_IMPORT_DESCRIPTOR)(import_descriptors_start + import_dir->Size);
		++import_descriptors)
	{
		if (!import_descriptors->Characteristics) break;

		for (PIMAGE_THUNK_DATA o_thunk = (PIMAGE_THUNK_DATA)(module_copy.get() + import_descriptors->OriginalFirstThunk),
			n_thunk = (PIMAGE_THUNK_DATA)(module_copy.get() + import_descriptors->FirstThunk);
			o_thunk->u1.AddressOfData != 0;
			++o_thunk, ++n_thunk
			)
		{
			if ((o_thunk->u1.AddressOfData & ORDINAL_IMPORT) != 0)
				continue;
			PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(module_copy.get() + o_thunk->u1.AddressOfData);
			if (!std::strcmp("HeapAlloc", import_by_name->Name))
			{
				uint32_t thunk_va = (uint32_t)((uint8_t*)n_thunk - module_copy.get());
				return (HeapAlloc_t*)((uint8_t*)process_module + thunk_va);
			}
		}
	}

	return nullptr;
}

void Injector::relocate(uint8_t dll_bytes[], size_t dll_size, uint8_t* new_image_base)
{
	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
	const PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(dll_bytes + dos_header->e_lfanew);

	const PIMAGE_DATA_DIRECTORY data_dir = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!data_dir->VirtualAddress || !data_dir->Size) return;
	PIMAGE_BASE_RELOCATION base_start = PIMAGE_BASE_RELOCATION(dll_bytes + virtual_to_file_address(data_dir->VirtualAddress, nt_header));
	const PIMAGE_BASE_RELOCATION base_end = PIMAGE_BASE_RELOCATION((uint8_t*)base_start + data_dir->Size);

	while (base_start < base_end && base_start->VirtualAddress)
	{
		const uint32_t reloc_base_fo = virtual_to_file_address(base_start->VirtualAddress, nt_header);
		PIMAGE_RELOCATION_ENTRY entries_start = (PIMAGE_RELOCATION_ENTRY)((uint8_t*)base_start + sizeof(IMAGE_BASE_RELOCATION));
		const PIMAGE_RELOCATION_ENTRY entries_end = (PIMAGE_RELOCATION_ENTRY)((uint8_t*)base_start + base_start->SizeOfBlock);

		for (;entries_start < entries_end && entries_start->Type ; entries_start++)
		{
			if (entries_start->Type != IMAGE_REL_BASED_DIR64)
			{
				std::cerr << "[-] unsupported relocation type\n";
				continue;
			}
			uint8_t** p_to_reloc = (uint8_t**)(dll_bytes + reloc_base_fo + entries_start->Offset);
			std::cout << "reloc: " << (void*)*p_to_reloc;
			*p_to_reloc =  new_image_base + (*p_to_reloc - (uint8_t*)nt_header->OptionalHeader.ImageBase);
			std::cout << " -> " << (void*)*p_to_reloc << '\n';
		}

		base_start = (PIMAGE_BASE_RELOCATION)entries_end;
	}
}

void Injector::set_imports(HookData* data)
{
	const uint8_t* image_base = data->module_base;
	const LoadLibraryA_t LoadLibraryA_address = data->LoadLibraryA_address;
	const GetProcAddress_t GetProcAddress_address = data->GetProcAddress_address;
	const VirtualProtect_t VirtualProtect_address = data->VirtualProtect_address;

	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
	const PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(image_base + dos_header->e_lfanew);

	VirtualProtect_address(data->p_HeapAlloc_IAT, 8, PAGE_READONLY, (DWORD*)&data->set_imports);

	import_table_fix:
	{
		const PIMAGE_DATA_DIRECTORY import_data_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!import_data_dir->VirtualAddress || !import_data_dir->Size) goto set_proper_page_prot;

		const PIMAGE_IMPORT_DESCRIPTOR dll_import_table_start = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + import_data_dir->VirtualAddress);
		const PIMAGE_IMPORT_DESCRIPTOR dll_import_table_end = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)dll_import_table_start + import_data_dir->Size);

		for
		(
			PIMAGE_IMPORT_DESCRIPTOR dll_import_entry = dll_import_table_start;
			dll_import_entry < dll_import_table_end && dll_import_entry->Characteristics;
			++dll_import_entry
		)
		{
			const char* dll_name = (const char*)image_base + dll_import_entry->Name;
			HMODULE dll = LoadLibraryA_address(dll_name);
			if (!dll) continue;
			for
			(
				PIMAGE_THUNK_DATA dll_import_lookup_table_entry = (PIMAGE_THUNK_DATA)(image_base + dll_import_entry->FirstThunk);
				dll_import_lookup_table_entry->u1.AddressOfData;
				dll_import_lookup_table_entry++
			)
			{
				if ((dll_import_lookup_table_entry->u1.AddressOfData & ORDINAL_IMPORT) != 0)
				{
					dll_import_lookup_table_entry->u1.Function = (ULONGLONG)GetProcAddress_address(dll, MAKEINTRESOURCEA(dll_import_lookup_table_entry->u1.Ordinal));
					continue;
				}
				PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(image_base + dll_import_lookup_table_entry->u1.AddressOfData);
				dll_import_lookup_table_entry->u1.Function = (ULONGLONG)GetProcAddress_address(dll, import_by_name->Name);
			}
		}
	}

	set_proper_page_prot:
	{
		const int number_of_sections = nt_headers->FileHeader.NumberOfSections;
		const PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers->OptionalHeader;
		PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((uint8_t*)optional_header + nt_headers->FileHeader.SizeOfOptionalHeader);

		for (int i = 0; i < number_of_sections; ++i, ++section)
		{
			DWORD protection = PAGE_READONLY;
			if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0U)
				protection = PAGE_READWRITE;
			else if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0U)
				protection = PAGE_EXECUTE_READ;
			VirtualProtect_address((void*)(image_base + section->VirtualAddress), section->Misc.VirtualSize, protection, (DWORD*)&data->set_imports);
		}
	}

	setup_exceptions:
	{
		PIMAGE_DATA_DIRECTORY exception_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (!exception_dir->Size) goto call_tls_entry_points;
		data->RtlAddFunctionTable_address((PIMAGE_RUNTIME_FUNCTION_ENTRY)(image_base + exception_dir->VirtualAddress), exception_dir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (uint64_t)image_base);
	}

	call_tls_entry_points:
	{
		const PIMAGE_DATA_DIRECTORY data_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (!data_dir->VirtualAddress || !data_dir->Size) goto call_main_entry_point;

		const PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)(image_base + data_dir->VirtualAddress);
		for (PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks; *callback; ++callback)
		{
			(*callback)((void*)image_base, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	call_main_entry_point:
	{
		typedef BOOL(*entry_point_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
		entry_point_t entry_point = (entry_point_t)(image_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
		entry_point((HINSTANCE)image_base, DLL_PROCESS_ATTACH, nullptr);
	}
}
