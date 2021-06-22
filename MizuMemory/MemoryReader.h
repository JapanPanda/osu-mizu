#pragma once

#ifdef _DEBUG
#define D(fmt, ...) fprintf(stderr, fmt,__VA_ARGS__);
#else
#  define D(x) do{}while(0)
#endif // DEBUG

// Developed specifically with OsuMizu in mind
#include "Windows.h"
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <stdexcept>

namespace MizuMemory {
    struct Signature {
        std::string pattern;
        // x means we consider it. ? is wildcard
        std::string mask;
    };

    struct Address {
        // If address is a multilevel pointer
        bool isPointer;
        DWORD baseAddress;
        std::vector<unsigned int> offsets;

        // Address
        DWORD address;
    };

    class MemoryReader {
    private:
        DWORD processId;
        HANDLE processHandle;
        std::unordered_map<std::wstring, MODULEENTRY32> moduleMap;

        void openProcess(const std::wstring& processName);
        void openModule(const std::wstring& moduleName);
    public:
        MemoryReader(const std::wstring& processName, const std::vector<std::wstring>& moduleNames);

        template <typename T>
        bool writeMemory(DWORD address, T value) const {
            return WriteProcessMemory(this->processHandle, (LPVOID)address, &value, sizeof(T), 0);
        }

        template <typename T>
        T readMemory(DWORD address) {
            T value;
            ReadProcessMemory(this->processHandle, (LPCVOID)address, &value, sizeof(T), NULL);
            return value;
        }

        // Scans for a signature
        Address scanSignature(const Signature& signature, char* begin, intptr_t size) const;

        // Scans for signature and resolves the pointer chain
        Address scanSignatureAndResolve(const Signature& signature, char* begin, intptr_t size, int offset, const std::vector<unsigned int>& ptrOffsets);

        void resolvePointerChain(Address& address);

        MODULEENTRY32 getModule(std::wstring moduleName) {
            if (this->moduleMap.find(moduleName) == this->moduleMap.end()) {
                std::wcerr << "Could not retrieve " << moduleName << " from the map." << std::endl;
                throw std::invalid_argument("Could not get non-existent module. Load it first or make sure you typed it right.");
            }
            return moduleMap[moduleName];
        }
    };
}
