#include "ProcessSelector.hpp"
#include <string>
#include <vector>
#include <optional>
#include <tlhelp32.h>
#include <iostream>


namespace
{
	struct ProcessInfo
	{
		std::wstring name;
		DWORD pid;
	};
	std::vector<ProcessInfo> processes{};
	bool update_processes(const std::wstring& name);
	bool print_process_list();
	DWORD get_pid_by_index(std::uint32_t index);
	void ask_proc_name();




	bool update_processes(const std::wstring& name)
	{
		if (name.empty()) return false;
		HANDLE h_processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!h_processes_snapshot) return false;

		std::vector<ProcessInfo> new_processes{};
		PROCESSENTRY32 current_process_entry{.dwSize = sizeof(PROCESSENTRY32)};
		if (Process32First(h_processes_snapshot, &current_process_entry))
		{
			while (Process32Next(h_processes_snapshot, &current_process_entry))
			{
				if (!current_process_entry.th32ProcessID || !std::wcslen(current_process_entry.szExeFile)) continue;
				std::wstring procname = current_process_entry.szExeFile;
				if (procname.find(name) == std::wstring::npos) continue;
				new_processes.push_back({ std::move(procname), current_process_entry.th32ProcessID });
			}
		}

		processes = std::move(new_processes);

		CloseHandle(h_processes_snapshot);
		return !processes.empty();
	}

	bool print_process_list()
	{
		if (processes.empty()) return false;

		for (int i = 0; i < processes.size(); ++i)
		{
			std::wcout << L"- " << i + 1 << L"  " << processes[i].name << L"  " << processes[i].pid << L'\n';
		}

		return true;
	}

	void ask_proc_name()
	{
		for (std::wstring input{}; !update_processes(input);)
		{
			if (!input.empty()) std::wcout << L"No process found\n";
			std::wcout << L"Enter process name: ";
			std::getline(std::wcin, input);
		}
	}

	DWORD get_pid_by_index(std::uint32_t index)
	{
		if (index >= processes.size()) return 0;
		return processes[index].pid;
	}
}

DWORD ProcessSelector::ask_pid()
{
	while (true)
	{
		processes.clear();
		ask_proc_name();
		std::wcout << L"- 0  Search for another process\n";
		print_process_list();
		while (true)
		{
			uint32_t selection = 0;
			std::wstring input{};
			std::wcout << L"Selection: ";
			std::getline(std::wcin, input);
			if (input.empty()) continue;
			selection = std::wcstoul(input.data(), nullptr, 10);
			if (selection == ULONG_MAX)
			{
				std::wcout << L"Invalid selection\n";
				continue;
			}
			if (selection > 0)
			{
				DWORD selected_pid = get_pid_by_index(selection - 1);
				if (selected_pid) return selected_pid;
			}
			break;
		}
	}
	return 0;
}
