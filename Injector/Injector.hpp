#pragma once
#include "../Process/Process.hpp"
#define ORDINAL_IMPORT (1ULL << 63)

class Injector
{
public:

	Injector(Process& process);
	void inject(uint8_t dll_bytes[], size_t dll_size);

private:

	typedef decltype(LoadLibraryA)* LoadLibraryA_t;
	typedef decltype(HeapAlloc)* HeapAlloc_t;
	typedef decltype(GetProcAddress)* GetProcAddress_t;
	typedef decltype(VirtualProtect)* VirtualProtect_t;
	typedef decltype(RtlAddFunctionTable)* RtlAddFunctionTable_t;

	struct HookData
	{
		HeapAlloc_t original_HeapAlloc_address;
		HeapAlloc_t* p_HeapAlloc_IAT; //this will be reset back to original_HeapAlloc_address
		uint8_t* module_base;
		LoadLibraryA_t LoadLibraryA_address;
		GetProcAddress_t GetProcAddress_address;
		VirtualProtect_t VirtualProtect_address;
		void(*set_imports)(HookData* data);
		RtlAddFunctionTable_t RtlAddFunctionTable_address;
		DWORD* buffer;
	};
	static void set_imports(HookData* data);

	Process& process;

	HeapAlloc_t* get_HeapAlloc_IAT();
	void relocate(uint8_t dll_bytes[], size_t dll_size, uint8_t* new_image_base);
};