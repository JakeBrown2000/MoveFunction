#include "main.h"

uint64_t convertStringToUInt(char* string){
    if(string[0] == '#'){
        string++;
    }
    
    char* endOfString = NULL;
    
    uint64_t value = strtoull(string, &endOfString, 16);
    
    if(*endOfString != '\0'){
        printERR("Failed to read the string");
        return 0;
    }
    else{
        return value;
    }
}

//TODO: uses
bool overwriteInstructionAtAddress(mach_vm_address_t addressOfInstruction, char* ARMInstruction){
    return true;
}

//TODO: here
bool fixupBLInstruction(cs_insn * insn, mach_vm_address_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved){
    mach_vm_address_t currentInstructionAddress = locationOfFunction + insn->address;
    printDBG("0x%llx", currentInstructionAddress);
    
    uint64_t branchLocationBeforeFixup = convertStringToUInt(insn->op_str);
    printDBG("Address of the BL prior to fixup is 0x%llx", branchLocationBeforeFixup);
    
    uint64_t branchLocationAfterFixup  = branchLocationBeforeFixup - relativeDistanceMoved; // Minus as we need to do the opposite of the move
    printDBG("Address of the BL after fixup is 0x%llx", branchLocationAfterFixup);
    
    return true;
}

//TODO: here
bool fixupADRPInstruction(cs_insn * insn, mach_vm_address_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved){
    return true;
}

/*
    debugCSInstruction
 
    prints all related information about the capstone instruction passed
 
    @Parameters:
        cs_insn * instruction - The instruction which is getting debugged
 
    @Returns:
        None
*/
void debugCSInstruction(cs_insn * instruction){
    printDBG("====================================== \n");
    printDBG("instruction->size:     %i   \n", instruction->size);
    printDBG("instruction->address:  %lli \n", instruction->address);
    printDBG("instruction->bytes:    %s   \n", instruction->bytes);
    printDBG("instruction->detail:   %p   \n", instruction->detail);
    printDBG("instruction->op_str:   %s   \n", instruction->op_str);
    printDBG("instruction->id:       %i   \n", instruction->id);
    printDBG("instruction->mnemonic: %s   \n", instruction->mnemonic);
    printDBG("====================================== \n");
}

/*
    checkForCorrectPageProtections
 
    Locates the memory page form the address passed in,
    Checks the VM Protections of the page and whether they are equal to the expected protections
    
    @Parameters:
        mach_vm_address_t addressOfPage - The address of the page which is being checked (should be trunc_page()'d)
        vm_prot_t    expectedProtection - The expected protections of the page (which we are checking for)
 
    @Returns:
        bool correctProtections - True if the current protections match expected protections, False if not
*/
bool checkForCorrectPageProtections(mach_vm_address_t addressOfPage, vm_prot_t expectedProtection){
    bool correctProtections = false;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    
    do{
        if(addressOfPage == 0){
            printERR("No page address passed");
            correctProtections = false;
            break;
        }
        
        if(expectedProtection == VM_PROT_NONE){
            printERR("No page protections passed");
            correctProtections = false;
            break;
        }
        
        mach_port_t objectName;
        
        mach_vm_size_t sizeOfPage = 0;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addressOfPage, &sizeOfPage, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &objectName);
        if(kr != KERN_SUCCESS){
            printERR("Failed checking page protections");
            correctProtections = false;
            break;
        }
        
        if(info.protection != expectedProtection){
            printDBG("Page passed does not have the correct protections");
            correctProtections = false;
            break;
        }
        
        printDBG("Page passed has the correct protections");
        correctProtections = true;
        
    }while(false);
    
    return correctProtections;
}

/*
    fixupHexValueInString
 
    Takes a string in the format of "#0x15004000" and adds the value of offset to it
 
    @Parameters:
        char * operand - The operand of an instruction (Whether that be X0, #0x24000 or just #0x24000
        int64_t offset - the offset which will be added to the operand parsed (this can be negative)
 
    @Returns:
        success - True if successful, False if not
*/
bool fixupHexValueInString(char* operand, int64_t offset){
    bool success = false;
    
    do{
        char* hexString = strstr(operand, "#0x");
        
        if(hexString == NULL){
            printf("No hex value found in operand string! \n");
            success = false;
            break;
        }
        
        hexString += 3; //ignore the #0x
        
        char * endptr;
        
        long int hexValue = strtol(hexString, &endptr, 16);
        
        if(hexValue == LONG_MAX || hexValue == LONG_MIN || endptr == hexString){
            printf("Invalid hex value! %s \n", hexString);
            success = false;
            break;
        }
        
        if(hexValue + offset > INT_MAX || hexValue + offset < INT_MIN){
            printf("Invalid hex value! Overflow / underflow detected \n");
            success = false;
            break;
        }
        
        hexValue += offset;
        
        char hexStringAfterFixup[19] = {'\0'}; // 19 Assumes a 64-bit integer
        
        snprintf(hexStringAfterFixup, sizeof(hexStringAfterFixup), "x%08lx", hexValue);
        strncpy(hexString - 1, hexStringAfterFixup, strlen(hexStringAfterFixup));
        
        success = true;
        
    }while(false);
    
    return success;
}

/*
    This funciton is used to fix the offsets of all branches whenever a function is moved.
    Instead of moving the stubs for standard library functions (such as printf() and dlopen() etc)
    We just incorporate the amount the function has moved (relativeDistanceMoved) into the address
    which is being branched too.
 
    Capstone Library does Disassembly (i.e. Machine Code / Hexadecimal -> ARM Assembly Code)
    Keystone Library does Assembly    (i.e. ARM Assembly Code -> Machine Code / Hexadecimal)
 
    IMPORTANT: Requires the page(s) which the function is mapped in are Readable & Writable
               If the page(s) are not, the protections will be changed to R/W
 
    Some functions do branching within the same function area, so we validate around that
    (I.E cbnz (Conditional Branch if not Zero) may branch a few instructions ahead but still within the same function,
     in which case, we do not want to incorporate the relativeDistanceMoved, as the branch is local to the function)
 
    @Parameters:
        uint64_t locationOfFunction    - The start location of the function in memory (after the move)
        size_t   sizeOfFunction        - The size of the function in bytes (divide by 4 to find number of instructions)
        int64_t  relativeDistanceMoved - This is the distance which the function has been moved when compared to the
                                         previous location of the function
                                         This is required to be a signed integer, as it is possible the function has
                                         been moved backwards relative to the previous locaiton
 
    @Returns:
        bool success - True if successful, False if not
    
*/
bool fixupFunctionOffsets(uint64_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved){
    printDBG("Fixing up function offsets for function at address: 0x%llx", locationOfFunction); //TODO: when implemented in metamorphic lib call locateFunctionFromAddress.
    bool success = false;
    // These two values are used to check if the branch will fall outside of the function location
    // If so we will need to fixup
    uint64_t beginningOfFunction = locationOfFunction;
    uint64_t endOfFunction       = beginningOfFunction + sizeOfFunction;
    
    do{
        if(locationOfFunction == 0){
            printERR("locaiton of function is 0, breaking early");
            success = false;
            break;
        }
        
        if(sizeOfFunction == 0){
            printERR("function Size is 0, breaking early");
            success = false;
            break;
        }
        
        if(relativeDistanceMoved == 0){
            printERR("No need to move fixup function offsets as relativeDistanceMoved was 0");
            success = false;
            break;
        }
        printDBG("Checking Page Protections");
        vm_prot_t expectedProtections = VM_PROT_READ | VM_PROT_WRITE;
        
        bool success = checkForCorrectPageProtections(mach_vm_trunc_page(locationOfFunction), expectedProtections);
        
        if(success == false){
            printDBG("Page passed in did not have the correct protections, changing them now");
            mach_vm_protect(mach_task_self(), trunc_page(locationOfFunction), sysconf(_SC_PAGESIZE), false, VM_PROT_READ | VM_PROT_WRITE);
        }
        
        csh handle;
        cs_insn *insn;
        
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK){
            printERR("Couldn't open Capstone disassembler handle");
            success = false;
            break;
        }
        
        size_t numberOfInstructions = cs_disasm(handle, (void*)locationOfFunction, sizeOfFunction, 0, 0, &insn);
        
        if(numberOfInstructions > 0){
            size_t j;
            for (j = 0; j < numberOfInstructions; j++) {
                printDBG("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                
                if(strcmp(insn[j].mnemonic,"bl") == 0){
                    debugCSInstruction(&insn[j]);
                    fixupBLInstruction(&insn[j], locationOfFunction, sizeOfFunction, relativeDistanceMoved);
                }
                else if(strcmp(insn[j].mnemonic,"adrp") == 0){
                    fixupADRPInstruction(&insn[j], locationOfFunction, sizeOfFunction, relativeDistanceMoved);
                }
            }
        }
        cs_close(&handle);
    }while(false);
    
    return success;
}

/*
    addTen
    
    A simple function which adds ten to the value passed in
    This is the function which will be moved in our example
 
    @Parameters:
        int num - the number which will have 10 added
 
    @Returns:
        int num - the original number after 10 has been added
 
*/
int addTen(int num){
    printDBG("Number: \n");
    num += 10;
    return num;
}

int main(int argc, const char * argv[]){
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
