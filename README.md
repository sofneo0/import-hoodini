# import-hoodini
Simple runtime import protection &amp; hook mitigation

A video demonstration of this can be found here: https://youtu.be/TWWLiTAPz1U

Import Hoodini is a simple concept of reversing the common usage of the Import Address Table.
The IAT (Import Address Table) is used in every native Windows application to allow modules to import routines which have been exported by other libraries/modules. Attackers will often abuse the IAT by either swapping the pointer to their own prologue OR by hooking the exported routine. This project mitigates and prevents these types of attacks by registering callbacks using small assembly stubs relative to every import which is responsbible for integrity checking them before allowing the call to commence. A snippet of this stub can be found below:
```asm
0:  48 81 ec 88 00 00 00    sub    rsp,0x88                     ; allocating stack space
7:  48 89 4c 24 28          mov    QWORD PTR [rsp+0x28],rcx     ; 'saving' the stack so that the original call can commence
c:  48 89 54 24 30          mov    QWORD PTR [rsp+0x30],rdx
11: 4c 89 44 24 38          mov    QWORD PTR [rsp+0x38],r8
16: 4c 89 4c 24 40          mov    QWORD PTR [rsp+0x40],r9
1b: 0f 11 44 24 48          movups XMMWORD PTR [rsp+0x48],xmm0
20: 0f 11 4c 24 58          movups XMMWORD PTR [rsp+0x58],xmm1
25: 0f 11 54 24 68          movups XMMWORD PTR [rsp+0x68],xmm2
2a: 0f 11 5c 24 78          movups XMMWORD PTR [rsp+0x78],xmm3
    
2f: 48 b9 fe ca be ba 00    movups rcx,0xbabecafe ; setting a1 (rcx) to the import's pointer
36: 00 00 00
39: 48 8d 54 24 28          lea    rdx,[rsp+0x28]
3e: 48 b8 ef be ad de 00    movabs rax,0xdeadbeef               ; call our 'callback' which handles integrity
45: 00 00 00
48: ff d0                   call   rax                        
		
4a: 48 8b 4c 24 28          mov    rcx,QWORD PTR [rsp+0x28]     ; restore the stack
4f: 48 8b 54 24 30          mov    rdx,QWORD PTR [rsp+0x30]
54: 4c 8b 44 24 38          mov    r8,QWORD PTR [rsp+0x38]
59: 4c 8b 4c 24 40          mov    r9,QWORD PTR [rsp+0x40]
5e: 0f 10 44 24 48          movups xmm0,XMMWORD PTR [rsp+0x48]
63: 0f 10 4c 24 58          movups xmm1,XMMWORD PTR [rsp+0x58]
68: 0f 10 54 24 68          movups xmm2,XMMWORD PTR [rsp+0x68]
6d: 0f 10 5c 24 78          movups xmm3,XMMWORD PTR [rsp+0x78]
72: 49 ba fe ca be ba 00    movups r10,0xbabecafe
79: 00 00 00
7c: 48 81 c4 88 00 00 00    add    rsp,0x88                  
83: 41 ff e2                jmp    r10                          ; call original export / imported routine
```


# Project Usage
Usage of this project is very simple. Simply include "import-hoodini.hpp" and call one of the following setups in your entrypoint.

A generic project may do the following which will simply protect ALL imported routines:
```cpp
ImportHoodini::Setup_AllImports();
ImportHoodini::ActivateImportCallbacks();
```

OR if you wish to specify a list of imports which should NOT be protected:
```cpp
// Basic refuse list for printf()
std::vector<std::uint64_t> RefuseList = {
  (std::uint64_t)&__stdio_common_vfprintf,
  (std::uint64_t)&__acrt_iob_func
};

ImportHoodini::Setup_AllImports(
  GetModuleHandleA(NULL),
  RefuseList
);

ImportHoodini::ActivateImportCallbacks();
```

OR if you wish to specify a list of imports which should ONLY be protected:
```cpp
// ONLY protect IsDebuggerPresent
std::vector<std::uint64_t> ProtectionList = {
  (std::uint64_t)&IsDebuggerPresent
};

ImportHoodini::Setup_Specific(
  GetModuleHandleA(NULL),
  ProtectionList
);
```




# Report System
Any time a function is hooked and ImportHoodini restores it, a report is made. 

These reports can be obtained by calling:
```cpp
ImportHoodini::Reports::GetReports();
```

The object in the std::vector<> return value contains the type of hook and also a function dump which is created when the hook is detected.




# --
Advantages of this project:
- Integrity checks functions inline and restores patches so that an attacker's hook is never hit
- Protection checks to ensure that VEH hooks and other sorts of protection hooks are not hit.
- Safe for multi-threaded projects/libraries
- Report system so that you can log all patches that are made. This will also create a report of the function dump. 
- Requires no macros or any code modifications to work.

Disadvantages/to-do:
- Uses STL therefore will require some changes to work in pure C modules 
- All imports in the callback function must be resolved before import protection is enabled
- Uses a disassembler to calculate function size (set to maximum of 0x20h bytes) however this does not handle near jumps and other instructions which could change order of execution.
- Ignores all imports from MSVCP140.dll & also free, malloc and realloc as they may cause deadlocks.
- This project assumes that patches / inline hooks are placed at the start of the prologue which is not always true therefore it will not detect hooks past 0x20 bytes into the prologue.

**Please ensure optimizations are disabled if you attempt to use this project!**

Credits to [@irql0](https://www.github.com/irql0) for assembly stub & other bits.
