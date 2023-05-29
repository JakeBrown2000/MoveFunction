#include "main.h"

/*
    disassembleFunction
 
    Disassembles a single function from machine code into readable ARM instructions
    All of the disassembled instructions are readable via calls to printDBG();
    DEBUG_MODE must be true for this to be readable
 
    @Parameters:
        void* functionStartAddress -
        size_t functionSize        -
 
    @Returns:
        None
 
 */
void disassembleFunction(mach_vm_address_t functionStartAddress, size_t functionSize){
    if(!functionStartAddress){
        printERR("NULL value parsed");
        return;
    }
    
    if(functionSize == 0){
        printERR("function Size is 0, breaking early");
        return;
    }
    
    csh handle;
    cs_insn *insn;
    
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK){
        printERR("Couldn't open Capstone disassembler handle");
        return;
    }
    
    size_t numberOfInstructions = cs_disasm(handle, (void*)functionStartAddress, functionSize, 0, 0, &insn);
    
    if(numberOfInstructions > 0){
        size_t j;
        for (j = 0; j < numberOfInstructions; j++) {
            printDBG("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
    }
    
    cs_close(&handle);
    return;
}


/*
    convertStringToUInt
 
    IMPORTANT: ASSUMES THE STRING IS IN HEXADECIMAL (base16)
    Takes a string in the following format - "#0x1000000" and converts it into a uint64_t
 
    @Parameters:
        char *  string - The hexadecimal value encoded as a char *
 
    @Returns:
        uint64_t value - The converted value as an unsigned integer
 
 */
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

/*
    overwriteInstructionAtAddress
 
    Takes an address of an instruction in memory and a new ARM instruction as input.
    It uses the Keystone Engine library to assemble the new ARM instruction into machine code.
    The encoded instruction is then written back to the specified address in memory, overwriting the original instruction.

    @Parameters:
        mach_vm_address_t addressOfInstruction - The address in memory of the instruction we are overwriting
        char * ARMInstruction - The ARM assembly instruction we are assembling using keystone into machine code
        
    @Returns:
        bool success - True if successfully overwritten, False if not
*/
bool overwriteInstructionAtAddress(mach_vm_address_t addressOfInstruction, char* ARMInstruction){
    //TODO: do while false
    ks_engine * ks;
    ks_err      err;
    size_t      count;
    size_t      size;
    
    unsigned char * encodedInstruction;
    
    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks); //TODO: set this up once and pass it around
    
    if(err != KS_ERR_OK){
        printERR("Failed to create keystone engine");
        return false;
    }
    
    if(ks_asm(ks, ARMInstruction, 0, &encodedInstruction, &size, &count) != KS_ERR_OK){
        printERR("ks_asm() failed with error: %u", ks_errno(ks));
        return false;
    }
    
    uint32_t instructionToWriteBack = encodedInstruction[0] | (encodedInstruction[1] << 8) | (encodedInstruction[2] << 16) | (encodedInstruction[3] << 24);
    
    memcpy((void*)addressOfInstruction, (void*)&instructionToWriteBack, sizeof(uint32_t));
    printDBG("Overwritten function at 0x%llx with Instruction %s (Encoded as %llu)", addressOfInstruction, ARMInstruction, instructionToWriteBack);
    
    err = ks_close(ks);
    
    if(err != KS_ERR_OK){
        printERR("Failed to close keystone engine");
        return false;
    }
    
    return true;
}

/*
    locateBeginningOfPage
 
    takes a memory location and finds the beginning of the page
    i.e. rounds down to the nearest page boundary
 
    By default on Apple Silicon based macs this is 0x4000, however uses _SC_PAGESIZE to increase portability
    
    Return value of 0x1 indicates an error, we cant use 0x0 as this may be correct in some incredibly unique edgecase,
    whereas 0x1 is always incorrect as it is not instruction / page aligned.
 
    @Parameters:
        uint32_t location - A memory address which falls somewhere withing a page
 
    @Returns:
        uint32_t beginningOfPage - The location of the lower page boundary of the location parsed in
*/
uint64_t locateBeginningOfPage(uint64_t location){
    uint64_t beginningOfPage = 0x0;
    uint64_t distanceIntoThePage = 0x0;
    do{
        if(location % 4 != 0){
            printERR("location parsed in is invalid (Not instruction aligned) - %llx", location);
            beginningOfPage = 0x1;
            break;
        }
        
        distanceIntoThePage = location % sysconf(_SC_PAGESIZE);
        
        if(distanceIntoThePage == 0){
            printDBG("location parsed was already beginning of page - 0x%llx", location);
            beginningOfPage = location;
            break;
        }
        
        beginningOfPage = location - distanceIntoThePage;
        
    }while(false);
    
    return beginningOfPage;
}

/*
    fixupBLInstruction
 
    Takes a location
*/
bool fixupBLInstruction(cs_insn * insn, mach_vm_address_t locationOfFunction, size_t sizeOfFunction, int64_t relativeDistanceMoved){
    
    bool success = false;
    
    do{
        if(insn == NULL){
            printERR("Instruction passed was NULL");
            success = false;
            break;
        }
        
        if(locationOfFunction == 0){
            printERR("location passed was invalid");
            success = false;
            break;
        }
        
        if(sizeOfFunction == 0){
            printERR("sizeOfFunction passed was NULL");
            success = false;
            break;
        }
        
        if(relativeDistanceMoved == 0){
            printERR("Relative Distance Moved was passed 0");
            success = false;
            break;
        }
        
        if(strcmp(insn->mnemonic, "bl") != 0){
            printERR("Instruction Passed was not a BL, this is the wrong function to be calling");
            success = false;
            break;
        }
        
        mach_vm_address_t currentInstructionAddress = locationOfFunction + insn->address;
        printDBG("ADDRESS OF CURRENT INSTRUCTION: 0x%llx", currentInstructionAddress);
        
        uint64_t branchLocationBeforeFixup = convertStringToUInt(insn->op_str);
        printDBG("Address of the BL prior to fixup is 0x%llx", branchLocationBeforeFixup);
        
        uint64_t branchLocationAfterFixup  = branchLocationBeforeFixup - relativeDistanceMoved; // Minus as we need to do the opposite of the move
        printDBG("Address of the BL after fixup is 0x%llx", branchLocationAfterFixup);
        
        char instructionString[0x100] = {'\0'};
        snprintf(instructionString, 0x100, "BL #0x%llx", branchLocationAfterFixup);
        
        overwriteInstructionAtAddress(currentInstructionAddress, instructionString);
        
        success = true;
        
    }while(false);
    
    return success;
    
}

/*
    updateLocationInString
    
    IMPORTANT: PLEASE ENSURE string IS A BUFFER OF LENGTH OF 0x100 SO THE UPDATING PROCESS DOES NOT OVERFLOW
    
    Takes a string such as "R0, #0x15000" and a new address "#0xffffffb000"
    And will update the first argument - "string" to instead be R0, #0xffffffb000
    Used when fixing up ADRP instructions.
 
    @Parameters:
        char * string -
        char * newLocation -
 
    @Returns:
        bool success - True if successful, False if not
*/
bool updateLocationInString(char* string, char* newLocation){
    bool success = false;
    
    do{
        if(string == NULL){
            printERR("String parsed as NULL");
            success = false;
            break;
        }
        
        if(newLocation == NULL){
            printERR("String parsed as NULL");
            success = false;
            break;
        }
        
        char *ptrToAddressInOriginalString = strstr(string, "#0x"); // check it actually contains an address
        if (ptrToAddressInOriginalString == NULL) {
            printERR("String didnt contain an address");
            success = false;
            break;
        }
        
        char *ptrToAddressInNewString = strstr(newLocation, "#0x");  // check it actually contains an address
        if (ptrToAddressInNewString == NULL) {
            printERR("String didnt contain an address");
            success = false;
            break;
        }
        
        size_t stringLength = strlen(ptrToAddressInNewString);
        strncpy(ptrToAddressInOriginalString, ptrToAddressInNewString, stringLength);
        success = true;
        
    }while(false);
    
    return success;
    
}

//TODO: here
bool fixupADRPInstruction(cs_insn * insn, mach_vm_address_t previousFunctionBeginning, mach_vm_address_t newFunctionBeginning, size_t sizeOfFunction){
    bool success = false;
    
    do{
        if(insn == NULL){
            printERR("Instruction passed was NULL");
            success = false;
            break;
        }
        
        if(previousFunctionBeginning == 0){
            printERR("previousFunctionBeginning passed was invalid");
            success = false;
            break;
        }
        
        if(newFunctionBeginning == 0){
            printERR("newFunctionBeginning passed was NULL");
            success = false;
            break;
        }
        
        if(sizeOfFunction == 0){
            printERR("sizeOfFunction was passed 0");
            success = false;
            break;
        }
        
        if(strcmp(insn->mnemonic, "adrp") != 0){
            printERR("Instruction Passed was not a ADRP, this is the wrong function to be calling");
            success = false;
            break;
        }
        
        uint64_t addressOfPreviousADRPInstruction = previousFunctionBeginning + insn->address;
        uint64_t pageOfPreviousADRPInstruction    = locateBeginningOfPage(addressOfPreviousADRPInstruction);
        printDBG("pageOfPreviousADRPInstruction: 0x%llx", pageOfPreviousADRPInstruction);
        
        uint64_t valueOfPreviousADRPOpcode = convertStringToUInt(&insn->op_str[5]); // get the value from string in following format: x0, #0x12345
        printDBG("valueOfADRPOpcode: 0x%llx", valueOfPreviousADRPOpcode);
        
        uint64_t locationOfDATA = pageOfPreviousADRPInstruction + valueOfPreviousADRPOpcode;
        printDBG("locationOfDATA: 0x%llx", locationOfDATA);
        
        uint64_t addressOfNewADRPInstruction = newFunctionBeginning + insn->address;
        uint64_t pageOfNewADRPInstruction    = locateBeginningOfPage(addressOfNewADRPInstruction);
        printDBG("pageOfNewADRPInstruction: 0x%llx", pageOfNewADRPInstruction);
        
        uint64_t relativeDistanceToMove = locationOfDATA - pageOfNewADRPInstruction;
        printDBG("relativeDistanceToMove: 0x%llx", relativeDistanceToMove);
        
        char operandString[0x100] = {'\0'};
        size_t stringLength = strlen(insn->op_str);
        
        char newLocationAsString[0x20] = {'\0'};
        snprintf(newLocationAsString, 0x20, "#0x%llx", relativeDistanceToMove);
        
        strncpy(operandString, insn->op_str, stringLength);
        updateLocationInString(operandString, newLocationAsString);

        printDBG("operand string is: %s", operandString);
        
        char instructionString[0x100] = {'\0'};
        snprintf(instructionString, 0x100, "adrp %s", operandString);
        
        printDBG("instruction string is: %s", instructionString);
        
        overwriteInstructionAtAddress(newFunctionBeginning + insn->address, instructionString);

        success = true;
        
    }while(false);
    
    return success;
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
    
    
    
    
    
    
 
    @Returns:
        bool success - True if successful, False if not
    
*/
bool fixupFunctionOffsets(mach_vm_address_t previousFunctionBeginning, mach_vm_address_t newFunctionBeginning, size_t sizeOfFunction){
    bool success = false;
    int64_t distanceMoved = newFunctionBeginning - previousFunctionBeginning;
    
    do{
        if(previousFunctionBeginning == 0){
            printERR("previousFunctionBeginning was passed as 0");
            success = false;
            break;
        }
        
        if(newFunctionBeginning == 0){
            printERR("newFunctionBeginning was passed as 0");
            success = false;
            break;
        }
        
        if(sizeOfFunction == 0){
            printERR("sizeOfFunction was passed as 0");
            success = false;
            break;
        }
        
        //TODO: This only checks the first page, if sizeOfFunction > sysconf(_SC_PAGESIZE) this may go wrong || FIXME
        vm_prot_t expectedProtections = VM_PROT_READ | VM_PROT_WRITE;
        success = checkForCorrectPageProtections(locateBeginningOfPage(newFunctionBeginning), expectedProtections);
        
        if(success == false){
            printDBG("Page passed did not have the correct protections, changing them now");
            kern_return_t kr = mach_vm_protect(mach_task_self(), locateBeginningOfPage(newFunctionBeginning), sysconf(_SC_PAGESIZE), false, expectedProtections);
            if(kr != KERN_SUCCESS){
                printERR("Failed to change page protections... breaking now!");
                success = false;
                break;
            }
        }
        
        csh handle = {0};
        cs_insn * insn = NULL;
        
        if(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK){
            printERR("Couldn't open Capstone disassembler handle");
            success = false;
            break;
        }
        
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        
        size_t numberOfInstructions = cs_disasm(handle, (void*)newFunctionBeginning, sizeOfFunction, 0, 0, &insn);
        
        if(numberOfInstructions <= 0){
            printERR("Incorrect number of Instructions returned from Capstone");
            cs_close(&handle);
            success = false;
            break;
        }
        
        for(size_t i = 0; i < numberOfInstructions; i++){
            printDBG("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
            if(strcmp(insn[i].mnemonic,"bl") == 0){
                debugCSInstruction(&insn[i]);
                fixupBLInstruction(&insn[i], newFunctionBeginning, sizeOfFunction, distanceMoved);
            }
            else if(strcmp(insn[i].mnemonic,"adrp") == 0){
                debugCSInstruction(&insn[i]);
                fixupADRPInstruction(&insn[i], previousFunctionBeginning, newFunctionBeginning, sizeOfFunction);
            }
        }
        
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
    dlopen("/tmp/exampleInjection.dylib", RTLD_NOW);
    num += 10;
    return num;
}

int main(int argc, const char * argv[]){
    addTen(7);

    task_t self_task = mach_task_self();
    mach_vm_address_t locationToWriteFunction = 0;
    int kr = 0;

    kr = mach_vm_allocate(self_task, &locationToWriteFunction, sysconf(_SC_PAGESIZE), VM_FLAGS_ANYWHERE | VM_FLAGS_FIXED);
    
    if(kr != KERN_SUCCESS){
        printERR("Error occured allocating memory: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }
    
    kr = mach_vm_protect(self_task, locationToWriteFunction, sysconf(_SC_PAGESIZE), false, VM_PROT_READ | VM_PROT_WRITE);
    
    if(kr != KERN_SUCCESS){
        printERR("Error occured setting R/W protections: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }
    
    printDBG("Copying machine code to new page! (Moving Function)");
    
    uint64_t originalFunctionLocation = (unsigned long)addTen;
    
    printDBG("=================================================================");
    printDBG("originalFunctionLocation: 0x%llx", originalFunctionLocation);
    printDBG("locationToWriteFunction:  0x%llx", locationToWriteFunction);
    printDBG("=================================================================");
    
    memcpy((void*)locationToWriteFunction, (void*)addTen, 0x48);
    
    fixupFunctionOffsets((mach_vm_address_t)(void*)addTen, locationToWriteFunction, 0x48);
    
    kr = mach_vm_protect(self_task, locationToWriteFunction, sysconf(_SC_PAGESIZE), false, VM_PROT_READ | VM_PROT_EXECUTE);
    
    if(kr != KERN_SUCCESS){
        printERR("Error occured setting R/X protections: %s \n", (char*)mach_error_string(kr));
        exit(0);
    }
    
    int64_t amountMoved = locationToWriteFunction - (uint64_t)addTen;
    printDBG("amount moved is: 0x%llx \n", amountMoved);

    disassembleFunction((mach_vm_address_t)addTen, 0x48);
    disassembleFunction((mach_vm_address_t)locationToWriteFunction, 0x48);
    
    int retValue = ((int(*)(int))(void*)locationToWriteFunction)(10);
    printDBG("Number: %i \n", retValue);

    return 0;
}
