
#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>

using namespace std;

ifstream peFile;
IMAGE_DOS_HEADER dos_header;

bool checker() {
    if(!peFile.is_open()) { // если вдруг его открыть не удалось, то выведем ошибку и выйдем
        cout << "Can't open file" << endl;
        return true;
    }
    peFile.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    if(peFile.bad() || peFile.eof()) { // если вдруг считать не удалось
        cout << "Unable to read IMAGE_DOS_HEADER" << endl;
        return true;
    }
    peFile.seekg(dos_header.e_lfanew); //Переходим на структуру IMAGE_NT_HEADERS и готовимся считать ее
    if(peFile.bad() || peFile.fail()) {
        cout << "Cannot reach IMAGE_NT_HEADERS" << endl;
        return true;
    }
    if(dos_header.e_magic != 'ZM') { // Первые два байта структуры должны быть MZ, но в
        cout << "IMAGE_DOS_HEADER signature is incorrect" << endl; // x86 обратный порядок
        return true; // следования байтов, мы сравниваем эти байты со значением 'ZM'
    }
    if((dos_header.e_lfanew % sizeof(DWORD)) != 0) { // Начало заголовка самого PE-файла (IMAGE_NT_HEADERS)
        cout << "PE header is not DWORD-aligned" << endl; // должно быть выровнено на величину DWORD
        return true; // иначе наш PE-файл некорректен
    }
    return false;
}

int main() {
    peFile.open("SpotifySetup.exe", ios::in | ios::binary);
    if(checker()) {
        return 0;
    }

    IMAGE_NT_HEADERS nt_header; // читать будем IMAGE_NT_HEADERS только без дата директорий
    peFile.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
    if(peFile.bad() || peFile.eof()) {
        cout << "Error reading IMAGE_NT_HEADERS32" << endl;
        return 0;
    }
    if(nt_header.Signature != 'EP') { // Проверяем, что наш файл - PE сигнатура
        cout << "Incorrect PE signature" << endl;
        return 0;
    }

    DWORD first_section = dos_header.e_lfanew + nt_header.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;

//переходим на первую секцию в таблице секций
    peFile.seekg(first_section);
    if(peFile.bad() || peFile.fail())
    {
        cout << "Cannot reach section headers" << endl;
        return 0;
    }
    cout << hex << showbase << left;

    cout << "Address of entry point: " << nt_header.OptionalHeader.AddressOfEntryPoint << endl;

    WORD numberOfSections = nt_header.FileHeader.NumberOfSections;
    for(WORD i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        peFile.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));
        cout << "Name: " << sectionHeader.Name << endl;
        cout << "Virtual address: " << hex << sectionHeader.VirtualAddress << endl;
        cout << "Characteristics: " << hex << sectionHeader.Characteristics << endl;
        cout << "Misc physical address: " << hex << sectionHeader.Misc.PhysicalAddress << endl;
        cout << "Misc virtual size: " << hex << sectionHeader.Misc.VirtualSize << endl;
        cout << "Number of Relocations: " << hex << sectionHeader.NumberOfRelocations << endl;
        cout << "Pointer to line numbers: " << hex << sectionHeader.PointerToLinenumbers << endl;
        cout << "Pointer to raw data: " << hex << sectionHeader.PointerToRawData << endl;
        cout << "Pointer to relocations: " << hex << sectionHeader.PointerToRelocations << endl;
        cout << "Size of raw data: " << hex << sectionHeader.SizeOfRawData << endl;
        cout << endl;
    }

    /*todo получить исполняемую часть файла в байтах
     * она лежит в .text. читаем с .text size байт
     */
}