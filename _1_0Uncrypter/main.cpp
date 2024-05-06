#include <iostream>
#include <windows.h>

int main(int argc, char** argv)
{
	const uint8_t sectionName1[] = { 0x2e, 0x5b, 0x31, 0x5d, 0x00 };
	const uint8_t sectionName2[] = { 0x2e, 0x5b, 0x30, 0x5d, 0x00 };
	uint32_t keySize = 0x1e, keyIndex = 0;
	DWORD writtenTo = 0;
	IMAGE_SECTION_HEADER* sectionHeader = nullptr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	uint8_t* file = nullptr, * encryptedFile = nullptr;
	uint8_t* key = nullptr;
	DWORD fileSize = 0, encryptedFileSize = 0;
	std::string fileName;
	int encFileIndex = 0, j = 0;

	if (argc < 2)
	{
		std::cout << "[-]Usage: ./nameoftool <path of the binary>";
		return 1;
	}

	for(int argIndex = 1; argIndex < argc; argIndex++)
	{
		fileName = argv[argIndex];
		hFile = CreateFileA(argv[argIndex], FILE_READ_ACCESS, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		fileSize = GetFileSize(hFile, &fileSize);
		printf("[*]Binary name: %s and size 0x%x\n", fileName.data(), fileSize);
		file = new uint8_t[fileSize];
		ZeroMemory(file, fileSize);

		if (!ReadFile(hFile, file, fileSize, nullptr, nullptr))
		{
			std::cout << "Couldn't read the file";
			continue;
		}

		//Some checks
		if (((IMAGE_DOS_HEADER*)file)->e_magic != 0x5a4d ||
			((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)file)->e_lfanew + file))->Signature != 0x4550)
		{
			std::cout << "This is not a MZ or PE header!";
			continue;
		}

		sectionHeader = (IMAGE_SECTION_HEADER*)(file + (((IMAGE_DOS_HEADER*)file)->e_lfanew + (((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)file)->e_lfanew + file))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64))));
		for (int i = 0; i < sizeof(sectionName1); i++)
		{
			if (sectionHeader->Name[i] != sectionName1[i])
			{
				std::cout << "Not the binary that I want!!";
				continue;
			}
		}
		sectionHeader++;
		for (int i = 0; i < sizeof(sectionName1); i++)
		{
			if (sectionHeader->Name[i] != sectionName2[i])
			{
				std::cout << "Not the binary that I want!!";
				continue;
			}
		}

		//Magic happening here
		fileName += ".DRSMXX";

		encryptedFile = file + sectionHeader->PointerToRawData + 0x174;
		encryptedFileSize = *(uint32_t*)(file + sectionHeader->PointerToRawData + 0x024);
		key = file + sectionHeader->PointerToRawData + 0x118;
		printf("[*]Encrypted binary size 0x%x\n", encryptedFileSize);
		printf("[+]Decrypting encrypted binary at file offset 0x%04llx\n", encryptedFile - file);

		encFileIndex = 0;
		do
		{
			if (encFileIndex % 3 == 0)
			{
				keyIndex++;
				if (keyIndex - 1 >= keySize)
					keyIndex = 0;

				j = 0;
				do
				{
					encryptedFile[encFileIndex] ^= j;
					j++;
				}while (j < 0xff);

				encryptedFile[encFileIndex] ^= 0x0f ^ key[keyIndex];
			}
			encFileIndex++;
		}while (encFileIndex < encryptedFileSize);
		CloseHandle(hFile);

		hFile = CreateFileA(fileName.data(), FILE_WRITE_ACCESS, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("[-]Couldn't create a new file for the extracted binary\n");
			continue;
		}
		if (!WriteFile(hFile, encryptedFile, encryptedFileSize, &writtenTo, nullptr))
		{
			std::cout << "Couldn't write to the file";
			continue;
		}
		CloseHandle(hFile);

		printf("[+]Binary extracted successfully, output name: %s \n\n", fileName.data());
	}

	return 0;
}