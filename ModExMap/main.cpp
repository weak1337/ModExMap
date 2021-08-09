#include "includes.h"
bool LoadDLL(const char* path, uintptr_t* copy, size_t* size) {
	if (!GetFileAttributesA(path))
		printf("File doesn't exist\n");

	std::ifstream sFile(path, std::ios::binary | std::ios::ate);

	if (sFile.fail())
		printf("Couldn't open filestream\n");

	*size = sFile.tellg();

	if (!*size)
		printf("File too short");

	*copy = (uintptr_t)malloc(*size);
	if (!*copy)
		printf("Error allocating memory in local process\n");
	printf("Allocated memory for dll in local process at: 0x%p\n", *copy);

	sFile.seekg(0, std::ios::beg);
	sFile.read((char*)*copy, *size);
	sFile.close();
	printf("Read file! Dump {%x, %x}\n", *(uint8_t*)*copy, *(uint8_t*)((uintptr_t)*copy + 1));
	return true;
}



int main() {



	uintptr_t base; size_t size;
	if (!LoadDLL("C:\\Users\\weak\\Desktop\\old projects\\OldStuff\\Helloworld\\x64\\Release\\Helloworld.dll", &base, &size)) {
		printf("Couldn't load dll\n");
		goto END;
	}
	if (!ModExMap::attach("PortalWars-Win64-Shipping.exe")) {
		printf("Couldn't attach to proc\n");
		goto END;
	}
		
	if (!ModExMap::map_dll((char*)base, size, true, true))
	{
		printf("Couldn't map dll\n");
		goto END;
	}
END:
	system("pause");
}