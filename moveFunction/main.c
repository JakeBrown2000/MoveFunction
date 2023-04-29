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
#include "capstone/capstone.h"
#include "keystone/keystone.h"

/*
    This funciton is used to fix the offsets of all branches whenever a function is moved.
    Instead of moving the stubs for standard library functions (such as printf() and dlopen() etc)
    We just incorporate the amount the function has moved (relativeDistanceMoved) into the address
    which is being branched too.
 
    Capstone Library does Disassembly (i.e. Machine Code / Hexadecimal -> ARM Assembly Code)
    Keystone Library does Assembly    (i.e. ARM Assembly Code -> Machine Code / Hexadecimal)
 
    IMPORTANT: Requires the page(s) which the function is mapped in are Readable & Writable
    TODO: Add validation check that the pages are marked as R/W | For now just call correctly
 
    Some functions do branching within the same function area, so we validate around that
    (I.E cbnz (Conditional Branch if not Zero) may branch a few instructions ahead but still within the same function,
     in which case, we do not want to incorporate the relativeDistanceMoved, as the branch is local to the function)
 
    @Parameters:
        uint64_t locationOfFunction    - The start location of the function in memory
        size_t   sizeOfFunction        - The size of the function in bytes (divide by 4 to find number of instructions)
        int64_t  relativeDistanceMoved - This is the distance which the function has been moved when compared to the
                                         previous location of the function
                                         This is required to be a signed integer, as it is possible the function has
                                         been moved backwards relative to the previous locaiton
 
    @Returns:
        bool success - True if successful, False if not
    
*/
bool fixupFunctionOffsets(uint64_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved){
    
    bool success = false;
    
    // These two values are used to check if the branch will fall outside of the function location
    // If so we will need to fixup
    uint64_t beginningOfFunction = locationOfFunction;
    uint64_t endOfFunction       = beginningOfFunction + sizeOfFunction;
    
    do{
        if(locationOfFunction == 0){
            printf("locaiton of function is 0, breaking early");
            success = false;
            break;
        }
        
        if(sizeOfFunction == 0){
            printf("function Size is 0, breaking early");
            success = false;
            break;
        }
        
        if(relativeDistanceMoved == 0){
            printf("No need to move fixup function offsets as relativeDistanceMoved was 0");
            success = false;
            break;
        }
        
        csh handle;
        cs_insn *insn;
        
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK){
            printf("Couldn't open Capstone disassembler handle");
            success = false;
            break;
        }
        
        size_t numberOfInstructions = cs_disasm(handle, (void*)locationOfFunction, sizeOfFunction, 0, 0, &insn);
        
        if(numberOfInstructions > 0){
            size_t j;
            for (j = 0; j < numberOfInstructions; j++) {
                printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                if(strcmp(insn[j].mnemonic,"bl") == 0){
                    int64_t  preSlidBranchLocation = strtoull(insn[j].op_str + 3, NULL, 16);
                    int64_t postSlidBranchLocation = preSlidBranchLocation - (relativeDistanceMoved + insn[j].address);
                    //Where insn[j] is the offset into the function (in bytes)
                    printf("==================================================== \n");
                    printf("The location of the branch before being fixed up is: 0x%x \n", (uint32_t)preSlidBranchLocation);
                    printf("The machine code for the instruction before being fixed up is: 0x%x \n", *((uint32_t*)(beginningOfFunction + insn[j].address)));
                    printf("==================================================== \n");
                    
                    ks_engine *ks;
                    ks_err err;
                    size_t count;
                    unsigned char *encode;
                    size_t size;

                    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
                    if (err != KS_ERR_OK) {
                        printf("ERROR: failed on ks_open(), quit\n");
                        return -1;
                    }

                    char instructionString[0x40];

                    snprintf(instructionString, 0x40, "BL #0x%llx", postSlidBranchLocation);

                    if (ks_asm(ks, instructionString, 0, &encode, &size, &count) != KS_ERR_OK) {
                        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
                    }
                    else
                    {
                        uint32_t instructionToWriteBack =  encode[0] | (encode[1] << 8) | (encode[2] << 16) | (encode[3] << 24);
                        
                        printf("The location of the branch after being fixed up is: 0x%llx \n", (uint64_t)postSlidBranchLocation);
                        printf("The machine code for the instruction after being fixed up is: 0x%x \n", instructionToWriteBack);
                        printf("==================================================== \n");
                        
                        memcpy((void*)(beginningOfFunction + insn[j].address), (void*)&instructionToWriteBack, 4);
                    }

                    ks_free(encode);
                    ks_close(ks);
                }
            }
        }
        
        cs_close(&handle);
    }while(false);
    
    return success;
}

int addTen(int num){
    printf("Number: %i \n", num);
    num += 10;
    return num;
}

int main(int argc, const char * argv[]) {
    addTen(7);
    
    task_t self_task = mach_task_self();
    mach_vm_address_t locationToWriteFunction = 0;
    int kr = 0;
    
    uint64_t pageOfFunction = trunc_page((unsigned long)addTen);
    
    printf("pageOfFunction: 0x%llx \n", pageOfFunction);
    
    kr = mach_vm_allocate(self_task, &locationToWriteFunction, sysconf(_SC_PAGESIZE), VM_FLAGS_ANYWHERE | VM_FLAGS_FIXED);
    
    if(kr != KERN_SUCCESS){
        printf("Error occured allocating memory: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }
    
    kr = mach_vm_protect(self_task, locationToWriteFunction, sysconf(_SC_PAGESIZE), false, VM_PROT_READ | VM_PROT_WRITE);
    
    if(kr != KERN_SUCCESS){
        printf("Error occured setting R/W protections: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }
    
    memcpy((void*)locationToWriteFunction, (void*)addTen, sysconf(_SC_PAGESIZE));
    
    fixupFunctionOffsets(locationToWriteFunction, 0x48, (uint64_t)locationToWriteFunction - (uint64_t)addTen);

    kr = mach_vm_protect(self_task, locationToWriteFunction, sysconf(_SC_PAGESIZE), false, VM_PROT_READ | VM_PROT_EXECUTE);
    
    if(kr != KERN_SUCCESS){
        printf("Error occured setting R/X protections: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }

    printf("Previous Location: %p \n", addTen);
    printf("New Location: 0x%llx \n", locationToWriteFunction);
    
    int64_t amountMoved = locationToWriteFunction - (uint64_t)addTen;
    printf("amount moved is: 0x%llx \n", amountMoved);

    int retValue = ((int(*)(int))(void*)locationToWriteFunction)(10);
    printf("Number: %i \n", retValue);

    return 0;
}
