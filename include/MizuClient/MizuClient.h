#pragma once
#include "MizuMemory/MemoryReader.h"

namespace Mizu {
    class MizuClient {
    private:
        MizuMemory::MemoryReader mizuMemory;
    public:
        MizuClient();
    };
}
