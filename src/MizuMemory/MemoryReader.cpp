#include "MizuMemory/MemoryReader.h"

using namespace MizuMemory;

// Opens the process matching a unicode string (case-insensitive)
void MemoryReader::openProcess(const std::wstring& processName) {
    this->processHandle = nullptr;
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    do
        if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
            this->processId = entry.th32ProcessID;
            CloseHandle(handle);
            this->processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, this->processId);
            D("Found process handle: %p with process id: %lu.\n", this->processHandle, this->processId);
            return;
        }
    while (Process32Next(handle, &entry));

    throw std::invalid_argument("Could not find the process. Please ensure that it's open and running.");

}

// Opens a module and stores it inside its hashmap for future use.
// Meant to be called after openProcess
void MemoryReader::openModule(const std::wstring& moduleName) {
    HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, this->processId);
    MODULEENTRY32 mEntry;
    mEntry.dwSize = sizeof(mEntry);

    do {
        if (!_wcsicmp(mEntry.szModule, moduleName.c_str())) {
            CloseHandle(hmodule);
            std::wstring moduleString(moduleName);
            this->moduleMap[moduleString] = mEntry;
            D("Found module: %ls.\n", moduleName.c_str());
            return;
        }
    } while (Module32Next(hmodule, &mEntry));

    std::wcerr << "Could not find the module " << moduleName << std::endl;
    // Need to print separately since can't pass a unicode string into invalid_argument AFAIK
    throw std::invalid_argument("Could not find the module, please see the error statement.");
}

MemoryReader::MemoryReader(const std::wstring& processName, const std::vector<std::wstring>& moduleNames) {
    this->openProcess(processName);

    for (const std::wstring& moduleName : moduleNames) {
        this->openModule(moduleName);
    }
}

char* scanMatch(const char* pattern, const char* mask, char* begin, intptr_t size) {
    intptr_t patternLen = strlen(mask);

    for (int i = 0; i < size; i++) {
        bool found = true;
        for (int j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j)) {
                found = false;
                break;
            }
        }
        if (found) {
            return (begin + i);
        }
    }
    return nullptr;
}

Address MemoryReader::scanSignature(const Signature& signature, char* begin, intptr_t size) const {
    char* match{ nullptr };
    SIZE_T bytesRead;
    DWORD oldprotect;
    char* buffer{ nullptr };
    MEMORY_BASIC_INFORMATION mbi;
    mbi.RegionSize = 0x1000;//

    VirtualQueryEx(this->processHandle, (LPCVOID)begin, &mbi, sizeof(mbi));

    for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize) {
        if (!VirtualQueryEx(this->processHandle, curr, &mbi, sizeof(mbi))) continue;
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

        delete[] buffer;
        buffer = new char[mbi.RegionSize];

        if (VirtualProtectEx(this->processHandle, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
            ReadProcessMemory(this->processHandle, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
            VirtualProtectEx(this->processHandle, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

            char* internalAddr = scanMatch(signature.pattern.c_str(), signature.mask.c_str(), buffer, (intptr_t)bytesRead);

            if (internalAddr != nullptr) {
                // calculate from internal to external
                match = curr + (internalAddr - buffer);
                break;
            }
        }
    }

    delete[] buffer;
    Address matchedAddress = { false, 0, {}, (DWORD)match };
    return matchedAddress;
}

// Find an address by signature and resolve a pointer chain (useful for finding addresses and resolving them all in one function call)
Address MemoryReader::scanSignatureAndResolve(const Signature& signature, char* begin, intptr_t size, int offset, const std::vector<unsigned int>& ptrOffsets = {}) {
    // find the base address
    Address signatureAddress = this->scanSignature(signature, begin, size);

    Address foundAddress;
    // read in the address located at an offset from the signature
    foundAddress.baseAddress = this->readMemory<DWORD>(signatureAddress.address + offset);

    // resolve the pointer if there are any offsets
    if (ptrOffsets.size() != 0) {
        foundAddress.isPointer = true;
        foundAddress.offsets = ptrOffsets;
        this->resolvePointerChain(foundAddress);
    } else {
        foundAddress.isPointer = false;
        foundAddress.offsets = {};
        foundAddress.address = foundAddress.baseAddress;
    }

    return foundAddress;
}

// Resolves a pointer chain and stores it in the parameter
void MemoryReader::resolvePointerChain(Address& address) {
    uintptr_t addr = address.baseAddress;

    for (const unsigned int offset : address.offsets) {
        ReadProcessMemory(this->processHandle, (BYTE*)addr, &addr, sizeof(addr), nullptr);
        addr += offset;
    }

    address.address = addr;
}
