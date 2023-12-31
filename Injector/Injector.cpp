#include "Injector.hpp"
#include "../PEParser/PEParser.hpp"

Injector::Injector(Process& process) :
	process(process)
{
}

void Injector::inject(const std::string& dll_path)
{
	LoadLibraryA_t LoadLibraryA_address = (LoadLibraryA_t)process.get_proc_address("Kernel32.dll", "LoadLibraryA");
	char* c_dll = (char*)dll_path.c_str();
	Process::RemoteMemoryHolder<char> remote_dll_path = process.remote_allocate<char>(dll_path.size() + 1, PAGE_READONLY);
	remote_dll_path.write(c_dll, dll_path.size() + 1);

	HeapAlloc_t* p_HeapAlloc_IAT = get_HeapAlloc_IAT();
	DWORD original_prot = process.set_protection((uint8_t*)p_HeapAlloc_IAT, 8, PAGE_READWRITE);
	HeapAlloc_t original_HeapAlloc_address = process.read_memory<HeapAlloc_t>(p_HeapAlloc_IAT);

	uint8_t assembly[] =
	{ 
		0x4C, 0x8B, 0x15, 0x62, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x1D, 0x53, 0x00, 0x00, 0x00, 0x4D, 0x89, 0x1A, 0x48, 
		0x89, 0x4C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x4C, 0x89, 0x4C, 0x24, 
		0x20, 0x48, 0x8B, 0x0D, 0x4D, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, 0x3B, 0x00, 0x00, 0x00, 
		0x48, 0x83, 0xC4, 0x28, 0x48, 0x8B, 0x05, 0x20, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC9, 0x48, 0x89, 0x0D, 0x16, 
		0x00, 0x00, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x48, 0x8B, 0x54, 0x24, 0x10, 0x4C, 0x8B, 0x44, 0x24, 0x18, 
		0x4C, 0x8B, 0x4C, 0x24, 0x20, 0xFF, 0xE0 
	};

	HookData data
	{
		original_HeapAlloc_address,
		p_HeapAlloc_IAT,
		LoadLibraryA_address,
		remote_dll_path.get()
	};

	Process::RemoteMemoryHolder<uint8_t> remote_data = process.remote_allocate<uint8_t>(sizeof(assembly) + sizeof(data), PAGE_EXECUTE_READWRITE);
	process.write_memory<uint8_t>(remote_data.get(), assembly, sizeof(assembly));
	process.write_memory<HookData>((HookData*)(remote_data.get() + sizeof(assembly)), data);

	process.write_memory<HeapAlloc_t>(p_HeapAlloc_IAT, (HeapAlloc_t)remote_data.get());
	while (process.read_memory<uint8_t>(remote_data.get() + sizeof(assembly)) != 0) {}
	process.set_protection((uint8_t*)p_HeapAlloc_IAT, 8, original_prot);
}

Injector::HeapAlloc_t* Injector::get_HeapAlloc_IAT()
{
	HMODULE process_module = process.get_module_handle("msvcrt.dll");
	MODULEINFO info = process.get_module_info(process_module);

	std::unique_ptr<uint8_t[]> module_copy = process.read_memory<uint8_t>((uint8_t*)process_module, info.SizeOfImage);
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_copy.get();
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(module_copy.get() + dos_header->e_lfanew);

	//fix imports
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
				uint32_t thunk_va = (uint8_t*)n_thunk - module_copy.get();
				return (HeapAlloc_t*)((uint8_t*)process_module + thunk_va);
			}
		}
	}

	return nullptr;
}
