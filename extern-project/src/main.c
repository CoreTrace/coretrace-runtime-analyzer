#include "StackUsageAnalyzer.hpp"
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/LLVMContext.h>
#include <iostream>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "usage: sa_consumer <file.c>\n";
        return 1;
    }

    return 0;
}
