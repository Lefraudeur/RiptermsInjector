#pragma once
#include <vector>
#include <Windows.h>

typedef struct _IMAGE_RELOCATION_ENTRY
{
    WORD Offset : 12;
    WORD Type : 4;
} 
IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

std::vector<PIMAGE_SECTION_HEADER> get_section_headers(PIMAGE_NT_HEADERS nt_headers);
uint32_t virtual_to_file_address(uint32_t virtual_address, PIMAGE_NT_HEADERS nt_headers);