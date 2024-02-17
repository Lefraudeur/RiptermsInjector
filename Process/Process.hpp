#pragma once
#include <Windows.h>
#include <memory>
#include <Psapi.h>
#include <vector>
#include <cstdint>
#include <string>
#include <iostream>
#include <array>
#include <initializer_list>


class Process
{
public:
	Process(const char* window_name);
	Process(const Process& o_process);
	Process(DWORD pid);
	Process();
	~Process();

	operator bool() const;
	Process& operator=(const char* window_name);
	void open(const char* window_name);
	void open(DWORD pid);

	void disableHooks();
	uint8_t* allocate_memory(uint8_t* address, size_t size, DWORD protection = PAGE_EXECUTE_READWRITE);
	void free_memory(uint8_t* address);
	uint8_t* get_proc_address(const std::string& dll_name, const std::string& proc_name);
	uint8_t* get_proc_address(HMODULE dll, const std::string& proc_name);
	DWORD set_protection(uint8_t* address, size_t size, DWORD new_protection); //returns old protection
	std::vector<HMODULE> get_hmodules();
	HMODULE get_module_handle(std::string dll_path);
	MODULEINFO get_module_info(HMODULE module);
	HMODULE get_main_module();

	class RemoteString
	{
	public:
		RemoteString(Process& process, const std::string& str);
		RemoteString(const RemoteString& o_remoteString);
		~RemoteString();

		operator uint8_t* ();
		const uint8_t* remote_string_addr;
		const std::string& string;
	private:
		Process& process;
	};

	template<unsigned int N> struct RemoteThreadData
	{
	public:
		friend class Process;
		inline RemoteThreadData() :
			parameters_count(N),
			parameters{ nullptr },
			return_value(nullptr)
		{
		}
		inline RemoteThreadData(const std::array<uint8_t*, N>& a_parameters) :
			RemoteThreadData()
		{
			static_assert(N <= 4 || N % 2 == 0, "Stack alignement issue, add a nullptr param");
			for (int i = 0; i < N; ++i)
			{
				parameters[i] = (i < 4 ? *(a_parameters.begin() + i) : *(a_parameters.end() - i - 3));
			}
		}
	private:
		const uint64_t parameters_count;
		uint8_t* parameters[N];
		uint8_t* return_value;
	};
	template<unsigned int N> inline uint8_t* create_remote_thread(uint8_t* function_address, const RemoteThreadData<N>& parameter, size_t commit_stack_size = 0)
	{
		uint8_t shellcode[] =
		{ 
			0x48, 0x83, 0xEC, 0x08, 0x57, 0x56, 0x53, 0x55, 0x48, 0x89, 0xCB, 0x48, 0xC7, 0xC6, 0x00, 0x00, 
			0x00, 0x00, 0x48, 0x8B, 0x3B, 0x48, 0x39, 0xF7, 0x74, 0x39, 0x48, 0x83, 0xFE, 0x00, 0x75, 0x06, 
			0x48, 0x8B, 0x4B, 0x08, 0xEB, 0x28, 0x48, 0x83, 0xFE, 0x01, 0x75, 0x06, 0x48, 0x8B, 0x53, 0x10, 
			0xEB, 0x1C, 0x48, 0x83, 0xFE, 0x02, 0x75, 0x06, 0x4C, 0x8B, 0x43, 0x18, 0xEB, 0x10, 0x48, 0x83, 
			0xFE, 0x03, 0x75, 0x06, 0x4C, 0x8B, 0x4B, 0x20, 0xEB, 0x04, 0xFF, 0x74, 0xF3, 0x08, 0x48, 0xFF, 
			0xC6, 0xEB, 0xC2, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xB8, 0xAF, 0xAF, 0xAF, 0xAF, 
			0xAF, 0xAF, 0xAF, 0xAF, 0xFF, 0xD0, 0x48, 0x89, 0xEC, 0x48, 0x89, 0x44, 0xFB, 0x08, 0x5D, 0x5B, 
			0x5E, 0x5F, 0x48, 0x83, 0xC4, 0x08, 0xC3 
		};

		*(uint8_t**)(shellcode + 0x5C) = function_address;
		uint8_t* allocated_shellcode = allocate_memory(nullptr, sizeof(shellcode), PAGE_EXECUTE_READ);
		write_memory<uint8_t>(allocated_shellcode, shellcode, sizeof(shellcode));

		RemoteThreadData<N>* allocated_td = (RemoteThreadData<N>*)allocate_memory(nullptr, sizeof(RemoteThreadData<N>), PAGE_READWRITE);
		write_memory<RemoteThreadData<N>>(allocated_td, parameter);

		HANDLE thread = CreateRemoteThread(process_handle, nullptr, commit_stack_size, (LPTHREAD_START_ROUTINE)allocated_shellcode, allocated_td, 0, nullptr);
		if (!thread)
		{
			free_memory(allocated_shellcode);
			free_memory((uint8_t*)allocated_td);
			return nullptr;
		}
		WaitForSingleObject(thread, INFINITE);
		const RemoteThreadData<N>& td = read_memory<RemoteThreadData<N>>(allocated_td);
		free_memory(allocated_shellcode);
		free_memory((uint8_t*)allocated_td);
		CloseHandle(thread);
		return td.return_value;
	}

	HMODULE loadLibrary(const std::string& name);

	template<typename T> inline std::unique_ptr<T[]> read_memory(T* address, int element_count)
	{
		if (!process_handle)
			return std::unique_ptr<T[]>{};
		std::unique_ptr<T[]> data = std::make_unique<T[]>(element_count);
		ReadProcessMemory(process_handle, address, data.get(), element_count * sizeof(T), nullptr);
		return data;
	}

	template<typename T> inline T read_memory(T* address)
	{
		if (!process_handle)
			return T();
		T buffer{};
		ReadProcessMemory(process_handle, address, &buffer, sizeof(T), nullptr);
		return buffer;
	}

	template<typename T> inline size_t write_memory(T* address, const T& data)
	{
		if (!process_handle)
			return 0;
		DWORD o = set_protection((uint8_t*)address, sizeof(T), PAGE_READWRITE);
		size_t bytes_written = 0;
		WriteProcessMemory(process_handle, address, &data, sizeof(T), &bytes_written);
		set_protection((uint8_t*)address, sizeof(T), o);
		return bytes_written;
	}

	template<typename T> inline size_t write_memory(T* address, T array[], int element_count)
	{
		if (!process_handle)
			return 0;
		DWORD o = set_protection((uint8_t*)address, sizeof(T) * element_count, PAGE_READWRITE);
		size_t bytes_written = 0;
		WriteProcessMemory(process_handle, address, array, sizeof(T) * element_count, &bytes_written);
		set_protection((uint8_t*)address, sizeof(T) * element_count, o);
		return bytes_written;
	}

	template<typename T>
	class RemoteMemoryHolder //unique
	{
	public:
		inline RemoteMemoryHolder(Process& process, T* remote_address) :
			process(process),
			remote_address(remote_address)
		{}

		inline RemoteMemoryHolder(RemoteMemoryHolder& other_memholder) :
			RemoteMemoryHolder(other_memholder.process, other_memholder.remote_address)
		{
			other_memholder.remote_address = nullptr;
		}
		inline ~RemoteMemoryHolder()
		{
			if (remote_address)
				process.free_memory((uint8_t*)remote_address);
			remote_address = nullptr;
		}

		inline T* get()
		{
			return remote_address;
		}

		inline operator T*()
		{
			return get();
		}

		inline T read()
		{
			return process.read_memory<T>(remote_address);
		}

		inline std::unique_ptr<T[]> read(int element_count)
		{
			return process.read_memory<T>(remote_address, element_count);
		}

		inline operator T()
		{
			return read();
		}

		inline size_t write(const T& new_data)
		{
			return process.write_memory<T>(remote_address, new_data);
		}

		inline size_t write(T array[], int element_count)
		{
			return process.write_memory<T>(remote_address, array, element_count);
		}
	private:
		Process& process;
		T* remote_address;
	};
	template<typename T> inline RemoteMemoryHolder<T> remote_allocate(DWORD protection)
	{
		return RemoteMemoryHolder<T>(*this, (T*)allocate_memory(nullptr, sizeof(T), protection));
	}

	template<typename T> inline RemoteMemoryHolder<T> remote_allocate(int element_count, DWORD protection)
	{
		return RemoteMemoryHolder<T>(*this, (T*)allocate_memory(nullptr, sizeof(T) * element_count, protection));
	}
private:
	HANDLE process_handle = nullptr;
	DWORD pid = 0;
};
