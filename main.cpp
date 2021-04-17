#include <iostream>
#include <windows.h>
#include <fstream>

using namespace std;

ifstream peFile;
IMAGE_DOS_HEADER dos_header;

bool checker() {
    if (!peFile.is_open()) { // если вдруг его открыть не удалось, то выведем ошибку и выйдем
        cout << "Can't open file" << endl;
        return true;
    }
    peFile.read(reinterpret_cast<char *>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    if (peFile.bad() || peFile.eof()) { // если вдруг считать не удалось
        cout << "Unable to read IMAGE_DOS_HEADER" << endl;
        return true;
    }
    peFile.seekg(dos_header.e_lfanew); //Переходим на структуру IMAGE_NT_HEADERS и готовимся считать ее
    if (peFile.bad() || peFile.fail()) {
        cout << "Cannot reach IMAGE_NT_HEADERS" << endl;
        return true;
    }
    if (dos_header.e_magic != 'ZM') { // Первые два байта структуры должны быть MZ, но в
        cout << "IMAGE_DOS_HEADER signature is incorrect" << endl; // x86 обратный порядок
        return true; // следования байтов, мы сравниваем эти байты со значением 'ZM'
    }
    if ((dos_header.e_lfanew % sizeof(DWORD)) != 0) { // Начало заголовка самого PE-файла (IMAGE_NT_HEADERS)
        cout << "PE header is not DWORD-aligned" << endl; // должно быть выровнено на величину DWORD
        return true; // иначе наш PE-файл некорректен
    }
    return false;
}

int main() {

    peFile.open("SpotifySetup.exe", ios::in | ios::binary);
    ofstream output("output.txt");
    ofstream bin("bin.txt");

    if (checker()) {
        return 0;
    }

    IMAGE_NT_HEADERS nt_header; // читать будем IMAGE_NT_HEADERS только без дата директорий
    peFile.read(reinterpret_cast<char *>(&nt_header), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
    if (peFile.bad() || peFile.eof()) {
        cout << "Error reading IMAGE_NT_HEADERS32" << endl;
        return 0;
    }
    if (nt_header.Signature != 'EP') { // Checking PE signature
        cout << "Incorrect PE signature" << endl;
        return 0;
    }

    DWORD first_section = dos_header.e_lfanew + nt_header.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) +
                          sizeof(DWORD) /* Signature */;

    //first section
    peFile.seekg(first_section);
    if (peFile.bad() || peFile.fail()) {
        cout << "Cannot reach section headers" << endl;
        return 0;
    }

    //Entry point
    output << "Address of entry point: " << nt_header.OptionalHeader.AddressOfEntryPoint << endl;
    output << hex << showbase << left;

    DWORD pCode, sizeOfCode;
    WORD numberOfSections = nt_header.FileHeader.NumberOfSections;
    //sections information
    for (WORD i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        peFile.read(reinterpret_cast<char *>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));
        output << "Name: " << sectionHeader.Name << endl;
        output << "Virtual address: " << hex << sectionHeader.VirtualAddress << endl;
        output << "Characteristics: " << hex << sectionHeader.Characteristics << endl;
        output << "Misc physical address: " << hex << sectionHeader.Misc.PhysicalAddress << endl;
        output << "Misc virtual size: " << hex << sectionHeader.Misc.VirtualSize << endl;
        output << "Number of Relocations: " << hex << sectionHeader.NumberOfRelocations << endl;
        output << "Pointer to line numbers: " << hex << sectionHeader.PointerToLinenumbers << endl;
        output << "Pointer to raw data: " << hex << sectionHeader.PointerToRawData << endl;
        output << "Pointer to relocations: " << hex << sectionHeader.PointerToRelocations << endl;
        output << "Size of raw data: " << hex << sectionHeader.SizeOfRawData << endl;
        output << endl;

        if (sectionHeader.Characteristics & 0x20) {
            pCode = sectionHeader.PointerToRawData;
            sizeOfCode = sectionHeader.SizeOfRawData;
        }
    }

    peFile.seekg(pCode);

    char code[sizeOfCode];

    peFile.read(code, sizeOfCode);
    bin.write(code, sizeOfCode);

    return 0;
}