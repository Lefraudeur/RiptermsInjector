#pragma once
#include "../Process/Process.hpp"
#define ORDINAL_IMPORT (1ULL << 63)

class Injector
{
public:
	Injector(Process& process);
	void inject(const std::string& dll_path);

private:
	typedef HMODULE(*LoadLibraryA_t)(LPCSTR lpLibFileName);
	typedef LPVOID(*HeapAlloc_t)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes);
	struct HookData
	{
		HeapAlloc_t original_HeapAlloc_address;
		HeapAlloc_t* p_HeapAlloc_IAT; //this will be reset back to original_HeapAlloc_address
		LoadLibraryA_t LoadLibraryA_address;
		const char* remote_dll_path;
	};
	Process& process;

	HeapAlloc_t* get_HeapAlloc_IAT();
};