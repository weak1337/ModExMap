#include "includes.h"
#include "shellcode.h"

bool is_32_bit;
int modcount;
DWORD pid;
uintptr_t base;
HANDLE prochandle;

template <typename T>
T read(uintptr_t addy) {
	T buffer;
	ReadProcessMemory(prochandle, (LPVOID)addy, &buffer, sizeof(T), 0);
	return buffer;
}
template <typename T>
void write(uintptr_t addy, T buffer) {
	WriteProcessMemory(prochandle, (LPVOID)addy, &buffer, sizeof(T), 0);
}


DWORD get_pid(const char* exename) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("Failed opening Snapshot! 0x%x", GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32{ 0 };
	pe32.dwSize = sizeof(pe32);

	BOOL status = Process32First(hSnap, &pe32);
	while (status) {
		if (!strcmp(pe32.szExeFile, exename)) {
			CloseHandle(hSnap);
			return pe32.th32ProcessID;
		}
		status = Process32Next(hSnap, &pe32);
	}
	CloseHandle(hSnap);
	return 0;
}
uintptr_t get_base(const char* modname, DWORD pid) {
	uintptr_t base_buffer = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("Failed opening Snapshot! 0x%x", GetLastError());
		return 0;
	}

	MODULEENTRY32 me32{ 0 };
	me32.dwSize = sizeof(me32);

	BOOL status = Module32First(hSnap, &me32);
	while (status) {
		if (!strcmp(me32.szModule, modname)) {
			base_buffer = (uintptr_t)me32.modBaseAddr;
			IsWow64Process(prochandle, (PBOOL)&is_32_bit);
		}
		status = Module32Next(hSnap, &me32);
		modcount++;
	}
	CloseHandle(hSnap);
	return base_buffer;
}

bool ModExMap::attach(const char* proc_name) {
	pid = get_pid(proc_name);
	if (!pid) {
		printf("Couldn't find process\n");
		return false;
	}
	prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (prochandle <= 0) {
		printf("Couldn't open handle with all access\n");
		return false;
	}
	base = get_base(proc_name, pid);
	if (!base) {
		printf("Couldn't get base. Guess its protected\n");
		return false;
	}

	if (is_32_bit)
		printf("Proc is 32bit\n");
	return TRUE;


}

extern "C"{
	__kernel_entry NTSTATUS
		NTAPI
		NtQueryInformationProcess(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL
		);

}
uintptr_t find_avail_memory(size_t size) {
	uintptr_t allocation = 0x0;
	PROCESS_BASIC_INFORMATION64 pI;
	NtQueryInformationProcess(prochandle, (PROCESSINFOCLASS)0, &pI, sizeof(pI), 0);
	if (is_32_bit) {
		pI.PebBaseAddress += 0x1000; //32 bit processes have 2 PEBs. Since we are 64 we get the 64 addy. + 1 page = 32bit
		_PEB32 peb = read<_PEB32>(pI.PebBaseAddress);
		
		DWORD first_entry = read<DWORD>(peb.Ldr + 0xC);
		while (peb.Ldr + 0xC != first_entry) { //Iterate all modules
			START:
			DWORD modbase = read<DWORD>(first_entry + 0x18);
			DWORD modsize = read<DWORD>(first_entry + 0x20);

			IMAGE_DOS_HEADER dos = read<IMAGE_DOS_HEADER>(modbase);
			IMAGE_NT_HEADERS32 nt = read<IMAGE_NT_HEADERS32>(modbase + dos.e_lfanew);

			DWORD end_of_curr_module = modbase + nt.OptionalHeader.SizeOfImage;
			DWORD to_allocate = end_of_curr_module;

			while (to_allocate % 0x10000 != 0) {
				to_allocate += 0x1;
			}
			DWORD skipped = to_allocate - end_of_curr_module;
			bool found = false;
			for (int i = 0; i <= (size / 0x1000); i++) {
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQueryEx(prochandle, (LPCVOID)(to_allocate + i * 0x1000), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (mbi.AllocationBase) {
					found = true;
					break;
				}
			}
			if (found) {
				first_entry = read<DWORD>(first_entry);
				goto START;
			}
			write<DWORD>(first_entry + 0x20, (DWORD)(size + modsize + skipped));
			IMAGE_NT_HEADERS32 NTFAKE = nt;
			NTFAKE.OptionalHeader.SizeOfImage = nt.OptionalHeader.SizeOfImage + skipped + size;
			DWORD old;
			VirtualProtectEx(prochandle, (LPVOID)(modbase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS32), PAGE_READWRITE, &old);
			write<IMAGE_NT_HEADERS32>(modbase + dos.e_lfanew, NTFAKE);
			VirtualProtectEx(prochandle, (LPVOID)(modbase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS32), old, &old);
			allocation = to_allocate;
			break;
		}
	

	}
	else
	{
		_PEB64 peb = read<_PEB64>(pI.PebBaseAddress);

		uintptr_t first_entry = read<uintptr_t>(peb.Ldr + 0x10);
		while (peb.Ldr + 0x10 != first_entry) { //Iterate all modules
		START2:
			uintptr_t modbase = read<uintptr_t>(first_entry + 0x30);
			uintptr_t modsize = read<uintptr_t>(first_entry + 0x40);

			IMAGE_DOS_HEADER dos = read<IMAGE_DOS_HEADER>(modbase);
			IMAGE_NT_HEADERS nt = read<IMAGE_NT_HEADERS>(modbase + dos.e_lfanew);

			uintptr_t end_of_curr_module = modbase + nt.OptionalHeader.SizeOfImage;
			uintptr_t to_allocate = end_of_curr_module;

			while (to_allocate % 0x10000 != 0) {
				to_allocate += 0x1;
			}
			uintptr_t skipped = to_allocate - end_of_curr_module;
			bool found = false;
			for (int i = 0; i <= (size / 0x1000); i++) {
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQueryEx(prochandle, (LPCVOID)(to_allocate + i * 0x1000), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (mbi.AllocationBase) {
					found = true;
					break;
				}
			}
			if (found) {
				first_entry = read<uintptr_t>(first_entry);
				goto START2;
			}
			write<uintptr_t>(first_entry + 0x40, (uintptr_t)(size + modsize + skipped));
			IMAGE_NT_HEADERS NTFAKE = nt;
			NTFAKE.OptionalHeader.SizeOfImage = nt.OptionalHeader.SizeOfImage + skipped + size;
			DWORD old;
			VirtualProtectEx(prochandle, (LPVOID)(modbase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &old);
			write<IMAGE_NT_HEADERS>(modbase + dos.e_lfanew, NTFAKE);
			VirtualProtectEx(prochandle, (LPVOID)(modbase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS), old, &old);
			allocation = to_allocate;
			break;
		}
	}


	return allocation;
}

DWORD get_export(const char* modname, const char* funcname) {
	uintptr_t base_buffer = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("Failed opening Snapshot! 0x%x", GetLastError());
	}

	MODULEENTRY32 me32{ 0 };
	me32.dwSize = sizeof(me32);

	BOOL status = Module32First(hSnap, &me32);
	while (status) {
		if (!_stricmp(me32.szModule, modname)) {
			uintptr_t base = (uintptr_t)me32.modBaseAddr;
			IMAGE_DOS_HEADER dos_header = { 0 };
			IMAGE_NT_HEADERS32 nt_headers = { 0 };

			if (!ReadProcessMemory(prochandle, (LPVOID)base, &dos_header, sizeof(dos_header), 0) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
				!ReadProcessMemory(prochandle, (LPVOID)(base + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), 0) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
				printf("ERROR\n");
				return 0;
			}



			const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

			if (!export_base || !export_base_size) {
				printf("ERROR\n");
				return 0;
			}


			const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

			if (!ReadProcessMemory(prochandle, (LPVOID)(base + export_base), export_data, export_base_size, 0))
			{
				VirtualFree(export_data, 0, MEM_RELEASE);
				printf("ERROR\n");
				return 0;
			}

			const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

			const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
			const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
			const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

			for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
				const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

				if (!_stricmp(current_function_name.c_str(), funcname)) {
					const auto function_ordinal = ordinal_table[i];
					const auto function_address = base + function_table[function_ordinal];

					if (function_address >= base + export_base && function_address <= base + export_base + export_base_size) {
						VirtualFree(export_data, 0, MEM_RELEASE);
						return 0; // No forwarded exports on 64bit?
					}

					VirtualFree(export_data, 0, MEM_RELEASE);
					return function_address;
				}
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return 0;


			CloseHandle(hSnap);
		}
		status = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	return 0;
}
template <typename T>
void map_sections(uintptr_t remote_base, char* img, T nt) {
	PIMAGE_SECTION_HEADER cSectionHeader = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++cSectionHeader) {
		if (cSectionHeader->SizeOfRawData) {
			if (WriteProcessMemory(prochandle, (char*)remote_base + cSectionHeader->VirtualAddress, (BYTE*)img + cSectionHeader->PointerToRawData, cSectionHeader->SizeOfRawData, 0)) {
				printf("Wrote %i section to %p\n", i, remote_base + cSectionHeader->VirtualAddress);
			}
			else
				printf("Failed writing %i section to %p error %x\n", i, remote_base + cSectionHeader->VirtualAddress, GetLastError());
		}
	}
}
template <typename T>
struct injectiondata {
	T loadlibrary;
	T getprocaddress;
	T dll;
};
bool ModExMap::map_dll(char* img, size_t disksize) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)img;
	DWORD shellcodesize = is_32_bit ? sizeof(shellcode32) : sizeof(shellcode64);
	PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)(img + dos->e_lfanew);
	PIMAGE_NT_HEADERS nt64 = (PIMAGE_NT_HEADERS)(img + dos->e_lfanew);
	DWORD totalsize = (is_32_bit ? nt32->OptionalHeader.SizeOfImage : nt64->OptionalHeader.SizeOfImage) + shellcodesize + disksize;

	uintptr_t remote_base = find_avail_memory(totalsize);
	VirtualAllocEx(prochandle, (LPVOID)remote_base, totalsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("Allocated at %p\n", remote_base);
	WriteProcessMemory(prochandle, (LPVOID)remote_base, img, 0x1000, 0);
	if(is_32_bit)
		map_sections(remote_base, img, nt32);
	else
		map_sections(remote_base, img, nt64);

	
	if (is_32_bit) {
		injectiondata<DWORD> data;
		data.loadlibrary = get_export("KERNEL32.DLL", "LoadLibraryA");
		data.getprocaddress = get_export("KERNELBASE.DLL", "GetProcAddress");
		data.dll = 0;
		write<injectiondata<DWORD>>(remote_base, data);
	}
	else
	{
		injectiondata<uintptr_t> data;
		data.loadlibrary = (uintptr_t)LoadLibraryA;
		data.getprocaddress = (uintptr_t)GetProcAddress;
		data.dll = 0;
		write<injectiondata<uintptr_t>>(remote_base, data);
	}
	
	WriteProcessMemory(prochandle, (LPVOID)(remote_base + totalsize - 0x1000), (LPVOID)(is_32_bit ? shellcode32 : shellcode64), shellcodesize,0);
	HANDLE ThreadHandle = CreateRemoteThread(prochandle, 0, 0, (LPTHREAD_START_ROUTINE)(remote_base + totalsize - 0x1000), (LPVOID)remote_base, 0, 0);
	CloseHandle(ThreadHandle);

	DWORD offset = is_32_bit ? 0x8 : 0x10;
	while (!read<DWORD>(remote_base + offset))
		Sleep(1000); //Wait for hdll to be set
	char buffer[0x1000];
	memset(buffer, 0, 0x1000);
	WriteProcessMemory(prochandle, (LPVOID)remote_base, buffer, sizeof(buffer), 0);
	CloseHandle(prochandle);
	free(img);
	return true;
}