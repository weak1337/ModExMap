namespace ModExMap {
	bool attach(const char* proc_name);
	bool map_dll(char* img, size_t disksize, bool wait_for_dllreturn, bool erasepeheader);
}