#include "Process.hpp"
#include <iostream>
#include <array>
#include <algorithm>
#include <string>
#include <fstream>
#include "../PEParser/PEParser.hpp"

Process::Process(const char* window_name)
{
	open(window_name);
}

Process::Process(const Process& o_process)
{
	this->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, o_process.pid);
	this->pid = o_process.pid;
}

Process::Process(DWORD pid)
{
	open(pid);
}

Process::Process()
{
}

Process::~Process()
{
	if (process_handle)
		CloseHandle(process_handle);
}

Process::operator bool() const
{
	return process_handle != nullptr;
}

Process& Process::operator=(const char* window_name)
{
	open(window_name);
	return *this;
}

void Process::open(const char* window_name)
{
	HWND process_window = FindWindowA(nullptr, window_name);
	if (!process_window)
	{
		std::cerr << "[-] Failed to get window\n";
		return;
	}
	DWORD l_pid = 0;
	GetWindowThreadProcessId(process_window, &l_pid);
	if (!l_pid)
	{
		std::cerr << "[-] Failed to get process ID\n";
		return;
	}
	open(l_pid);
}

void Process::open(DWORD pid)
{
	if (process_handle)
		CloseHandle(process_handle);
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	this->pid = pid;
}

uint8_t* Process::allocate_memory(uint8_t* address, size_t size, DWORD protection)
{
	if (!process_handle)
		return nullptr;
	return (uint8_t*)VirtualAllocEx(process_handle, address, size, MEM_COMMIT | MEM_RESERVE, protection);
}

void Process::free_memory(uint8_t* address)
{
	VirtualFreeEx(process_handle, address, 0, MEM_RELEASE);
}

uint8_t* Process::get_proc_address(const std::string& dll_name, const std::string& proc_name)
{
	HMODULE m = get_module_handle(dll_name);
	if (!m)
		m = loadLibrary(dll_name);
	return get_proc_address(m, proc_name);
}

uint8_t* Process::get_proc_address(HMODULE dll, const std::string& proc_name)
{
	if (!dll) return nullptr;
	MODULEINFO info{};
	GetModuleInformation(process_handle, dll, &info, sizeof(MODULEINFO));

	std::unique_ptr<uint8_t[]> module_copy = read_memory<uint8_t>((uint8_t*)dll, info.SizeOfImage);
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_copy.get();
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(module_copy.get() + dos_header->e_lfanew);
	PIMAGE_DATA_DIRECTORY export_data_dir_loc = (PIMAGE_DATA_DIRECTORY)&nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!export_data_dir_loc->VirtualAddress || !export_data_dir_loc->Size) return nullptr;
	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_copy.get() + export_data_dir_loc->VirtualAddress);
	if (!export_dir->AddressOfNames) return nullptr;
	uint32_t names_count = export_dir->NumberOfNames;
	uint32_t* names = (uint32_t*)(module_copy.get() + export_dir->AddressOfNames);

	for (uint32_t i = 0; i < names_count; ++i)
	{
		const char* name = (const char*)module_copy.get() + names[i];
		if (proc_name == name)
		{
			uint16_t* ordinals = (uint16_t*)(module_copy.get() + export_dir->AddressOfNameOrdinals);
			uint16_t ordinal = ordinals[i];
			uint32_t* functions = (uint32_t*)(module_copy.get() + export_dir->AddressOfFunctions);
			uint32_t function_rva = functions[ordinal];
			return (uint8_t*)dll + function_rva;
		}
	}
	return nullptr;
}

DWORD Process::set_protection(uint8_t* address, size_t size, DWORD new_protection)
{
	if (!process_handle)
		return 0;
	DWORD old_prot = 0;
	VirtualProtectEx(process_handle, address, size, new_protection, &old_prot);
	return old_prot;
}

std::vector<HMODULE> Process::get_hmodules()
{
	std::vector<HMODULE> modules(1);
	DWORD modules_size = 0;
	EnumProcessModulesEx(process_handle, modules.data(), 1, &modules_size, LIST_MODULES_64BIT);
	modules.resize(modules_size / sizeof(HMODULE));
	EnumProcessModulesEx(process_handle, modules.data(), modules_size, &modules_size, LIST_MODULES_64BIT);
	return modules;
}

HMODULE Process::get_module_handle(std::string dll_path)
{
	for (char& c : dll_path)
		c = std::tolower(c);

	for (HMODULE module : get_hmodules())
	{
		char module_base_name[FILENAME_MAX + 1] = { 0 };
		GetModuleBaseNameA(process_handle, module, module_base_name, FILENAME_MAX);
		std::string module_base_name_str = module_base_name;
		for (char& c : module_base_name_str)
			c = std::tolower(c);
		if (module_base_name_str != dll_path) continue;

		return module;
	}

	return nullptr;
}

MODULEINFO Process::get_module_info(HMODULE module)
{
	MODULEINFO info{};
	GetModuleInformation(process_handle, module, &info, sizeof(MODULEINFO));
	return info;
}

HMODULE Process::get_main_module()
{
	char process_name[FILENAME_MAX + 1] = { 0 };
	GetModuleBaseNameA(process_handle, nullptr, process_name, FILENAME_MAX);
	for (HMODULE module : get_hmodules())
	{
		char module_base[FILENAME_MAX + 1] = { 0 };
		GetModuleBaseNameA(process_handle, module, module_base, FILENAME_MAX);
		if (!std::strcmp(module_base, process_name))
			return module;
	}
	return nullptr;
}

HMODULE Process::loadLibrary(const std::string& name)
{
	uint8_t* loadLibraryA = get_proc_address("Kernel32.dll", "LoadLibraryA");
	HMODULE loaded = (HMODULE)create_remote_thread<1>(loadLibraryA, RemoteThreadData<1>({ RemoteString(*this, name) }));
	return loaded;
}

void Process::disableHooks()
{

	for (HMODULE module : get_hmodules())
	{
		MODULEINFO info{};
		char module_base[FILENAME_MAX + 1] = { 0 };
		GetModuleBaseNameA(process_handle, module, module_base, FILENAME_MAX);
		char module_path[MAX_PATH + 1] = { 0 };
		GetModuleFileNameExA(process_handle, module, module_path, MAX_PATH);
		GetModuleInformation(process_handle, module, &info, sizeof(MODULEINFO));
		std::cout << module_base << '\n';

		uint8_t* module_base_addr = (uint8_t*)module;
		std::unique_ptr<uint8_t[]> module_copy = read_memory(module_base_addr, info.SizeOfImage);

		
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_copy.get();
		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(module_copy.get() + dos_header->e_lfanew);

		std::ifstream dllfile(module_path, std::ios::binary);
		if (!dllfile) continue;

		for (PIMAGE_SECTION_HEADER section : get_section_headers(nt_header))
		{
			if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

			uint8_t* start = module_copy.get() + section->VirtualAddress;

			std::string_view sv((char*)start, section->SizeOfRawData);
			std::vector<uint8_t*> jmps{};
			for (size_t it = sv.find('\xE9', 0); it != sv.npos; it = sv.find('\xE9', ++it))
			{
				uint8_t* found = start + it;
				uint32_t offset = (uint32_t)(found - module_copy.get());
				jmps.push_back(module_base_addr + offset);
			}

			for (uint8_t* jmp : jmps)
			{
				uint32_t offset = (uint32_t)(jmp - module_base_addr);
				uint8_t* possible_modified_bytes = module_copy.get() + offset;
				uint32_t virtual_section_offset = offset - section->VirtualAddress;
				uint32_t file_offset = section->PointerToRawData + virtual_section_offset;

				dllfile.seekg(file_offset, std::ios::beg);
				uint8_t read_bytes[5] = { 0 };
				dllfile.read((char*)read_bytes, 5);

				if (!memcmp(possible_modified_bytes, read_bytes, 5)) continue; //all is ok
				//Hook detected
				//try to restore original bytes
				write_memory(jmp, read_bytes, 5);
				std::cout << "   Removed jmp at: " << (void*)jmp << "\n";
			}
		}
	}

	std::cout << "done" << '\n';
}


Process::RemoteString::RemoteString(Process& process, const std::string& str):
	process(process),
	string(str),
	remote_string_addr(process.allocate_memory(nullptr, str.size() + 1, PAGE_READONLY))
{
	const char* c_str = str.c_str();
	process.write_memory<char>((char*)remote_string_addr, (char*)c_str, (int)(str.size() + 1));
}

Process::RemoteString::RemoteString(const RemoteString& o_remoteString):
	RemoteString(o_remoteString.process, o_remoteString.string)
{
}

Process::RemoteString::~RemoteString()
{
	if (remote_string_addr)
		process.free_memory((uint8_t*)remote_string_addr);
}

Process::RemoteString::operator uint8_t* ()
{
	return (uint8_t*)remote_string_addr;
}
