#include <string>
#include <fstream>
#include <iostream>
#include <Windows.h>
#include "Process/Process.hpp"
#include "PEParser/PEParser.hpp"
#include <filesystem>
#include "Injector/Injector.hpp"
#include "dll/dll.dll.hpp"

int main(int argc, const char* argv[])
{
	Process process{"Lunar Client 1.8.9 (v2.13.2-2402)"};
	while (!process)
	{
		std::string window_name{};
		std::cout << "Window name: ";
		std::getline(std::cin, window_name);
		process = window_name.c_str();
		if (!process)
			std::cerr << "[-] Failed to open target process\n";
	}

	Injector injector(process);
	injector.inject((uint8_t*)dll_dll.data(), dll_dll.size());

	return 0;
}