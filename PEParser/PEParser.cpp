#include "PEParser.hpp"

std::vector<PIMAGE_SECTION_HEADER> get_section_headers(PIMAGE_NT_HEADERS nt_headers)
{
	int number_of_sections = nt_headers->FileHeader.NumberOfSections;
	std::vector<PIMAGE_SECTION_HEADER> section_headers{};
	section_headers.reserve(number_of_sections);

	PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers->OptionalHeader;
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((uint8_t*)optional_header + nt_headers->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < number_of_sections; ++i, ++section)
	{
		section_headers.push_back(section);
	}

	return section_headers;
}

uint32_t virtual_to_file_address(uint32_t virtual_address, PIMAGE_NT_HEADERS nt_headers)
{
	for (PIMAGE_SECTION_HEADER section : get_section_headers(nt_headers))
	{
		if ((virtual_address >= section->VirtualAddress)
			&& (virtual_address < section->VirtualAddress + section->Misc.VirtualSize))
		{
			uint32_t offset = virtual_address - section->VirtualAddress;
			return section->PointerToRawData + offset;
		}
	}
	return 0;
}
