#ifndef main_h
#define main_h

#include "capstone/capstone.h"
#include "keystone/keystone.h"
#include "Debug/Debug/Debug.h"

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <mach-o/dyld.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach_vm.h>

uint64_t convertStringToUInt(char* string);

bool fixupBLInstruction(cs_insn * insn, mach_vm_address_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved);
bool fixupADRPInstruction(cs_insn * insn, mach_vm_address_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved);

void debugCSInstruction(cs_insn * instruction);
bool checkForCorrectPageProtections(mach_vm_address_t addressOfPage, vm_prot_t expectedProtection);
bool fixupHexValueInString(char* operand, int64_t offset);
bool fixupFunctionOffsets(uint64_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved);
int addTen(int num);
int main(int argc, const char * argv[]);


#endif /* main_h */
