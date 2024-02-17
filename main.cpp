#include <string>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include "Process/Process.hpp"
#include "PEParser/PEParser.hpp"
#include <filesystem>
#include "Injector/Injector.hpp"
#include "dll/dll.dll.hpp"
#include "ProcessSelector/ProcessSelector.hpp"

int main(int argc, const char* argv[])
{

	DWORD pid = ProcessSelector::ask_pid();

	Process process{ pid };
	if (!process)
	{
		std::cerr << "[-] Failed to open target process\n";
		return -1;
	}

	Injector injector(process);
	injector.inject((uint8_t*)dll_dll.data(), dll_dll.size());

	return 0;
}