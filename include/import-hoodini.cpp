#include "import-hoodini.hpp"

// Additional dependencies
#include <intrin.h>
#include "hde/hde64.h"
#include <mutex>

namespace ImportHoodini
{	
	namespace Internal
	{
		size_t GetFunctionSize(std::uint8_t* Function)
		{
			size_t PTargetFnSize = 0;
			hde64s HDEObject;

			// Max fn size is 0x1000 (4096 bytes)
			while (PTargetFnSize < 0x1000)
			{
				hde64_disasm(&Function[PTargetFnSize], &HDEObject);

				if (HDEObject.flags & F_ERROR)
					break;

				// Instructions with opcode ret are usually one byte large,
				// however ret instruction of 0xC2 can disassemble to a slightly larger
				// instruction. I haven't seen this used in any win32 modules
				// so it won't be included however is food for thought!
				// Note that this function does NOT follow near jumps to gather all
				// possible paths of execution, it will simply measure up to the first
				// ret instruction OR trap to debugger (padding).
				if (Function[PTargetFnSize] == 0xCC)
					break; // Padding located
				else if (Function[PTargetFnSize] == 0xC3)
					break; // Ret located

				PTargetFnSize += HDEObject.len;
			}

			return PTargetFnSize;
		}

		// std::vector{OgFirstThunk, FirstThunk}
		std::vector<std::pair<IMAGE_THUNK_DATA*, IMAGE_THUNK_DATA*>> FetchImports(std::uint64_t ImageBase)
		{
			std::vector<std::pair<IMAGE_THUNK_DATA*, IMAGE_THUNK_DATA*>> Imports;

			const auto DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
			const auto NtHeader = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);

			const auto ImportsDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

			char* LibraryName = nullptr;
			HMODULE EnumLibrary = 0;
			auto ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(ImportsDirectory.VirtualAddress + ImageBase);
			while (ImportDescriptor->Name != NULL)
			{
				LibraryName = (char*)ImportDescriptor->Name + ImageBase;

				// Skip this as this contains mutex locks imports
				// that cannot be handled.
				if (std::string(LibraryName) != "MSVCP140.dll")
				{
					EnumLibrary = LoadLibraryA(LibraryName);

					if (EnumLibrary)
					{
						auto OgFirstThunk = (IMAGE_THUNK_DATA*)(ImageBase + ImportDescriptor->OriginalFirstThunk);
						auto FirstThunk = (IMAGE_THUNK_DATA*)(ImageBase + ImportDescriptor->FirstThunk);

						while (OgFirstThunk->u1.AddressOfData != NULL)
						{
							// Disallow free, malloc & realloc
							const auto PImportByName = (IMAGE_IMPORT_BY_NAME*)(ImageBase + OgFirstThunk->u1.AddressOfData);
							const auto AsciiImportName = std::string(PImportByName->Name);
							if (AsciiImportName != "free" && AsciiImportName != "malloc" && AsciiImportName != "realloc")
							{
								Imports.push_back({
									OgFirstThunk,
									FirstThunk
									});
							}

							++OgFirstThunk;
							++FirstThunk;
						}
					}
				}

				ImportDescriptor++;
			}

			return Imports;
		}

		DWORD GetPageProtection(void* PPage)
		{
			MEMORY_BASIC_INFORMATION MemInfo;
			
			if (VirtualQuery(PPage, &MemInfo, sizeof(MemInfo)))
				return MemInfo.Protect;

			// Return RX for default as it's fairly likely
			// to be RX.
			return PAGE_EXECUTE_READ;
		}
	}

	// Mutex for thread lock (requirement)
	static std::mutex ThreadLock;

	namespace Reports
	{		
		std::vector<HoodiniCallbackReport> ReportsList;

		// Thread safety must be considered here as ReportsList is constantly being pushed by the
		// callback and therefore could result in an exception if we try to access ReportsList
		// while it's being written to.
		std::vector<HoodiniCallbackReport> GetReports()
		{
			std::scoped_lock GetReportsLock(ThreadLock);
			
			return ReportsList;
		}
	}

	class HoodiniImport
	{
	public:
		bool SetupSuccess = false;

		char ImportName[0x32];
		std::uint64_t* PPFunction;
		std::uint64_t OgPFunction;

		// Stored here so that we can check it against the page protection in the future.
		DWORD OgPageProtection;

		// Note from author: 
		// It is possible that an attacker could possibly
		// 'sig scan' for the original bytes before patching
		// and then modify this as well as the function inline
		// to bypass this - therefore I suggest that this should
		// be xor'd with some sort of simple key whether it be
		// contextless or not.
		// Please note that the size of this OriginalFunction is
		// capped at 32 bytes OR the first ret (0xC3) or trap
		// to debugger (0xCC) instruction using hde64's disasm.
		// This will NOT handle near jumps or other instructions
		// that could affect rip / the order of execution.
		std::vector<uint8_t> OriginalFunction;

		// Constructor
		HoodiniImport(std::uint64_t ImageBase, IMAGE_THUNK_DATA* OgFirstThunk, IMAGE_THUNK_DATA* FirstThunk)
		{
			if (OgFirstThunk && FirstThunk)
			{
				// Set function & other data
				this->PPFunction = &FirstThunk->u1.Function;
				if (*this->PPFunction)
				{
					this->OgPFunction = *this->PPFunction;

					// Locate the name
					const auto PImportByName = (IMAGE_IMPORT_BY_NAME*)(ImageBase + OgFirstThunk->u1.AddressOfData);
					
					// Try to get the real name.
					strcpy_s(this->ImportName, "???");
					if (PImportByName)
					{
						// Copy the name (going to use STL for this as it's just easier)...
						const auto AsciiImportName = std::string(PImportByName->Name);
						if (AsciiImportName.length() > 0x3)
							strcpy_s(this->ImportName, AsciiImportName.c_str());
					}
					
					// Get the page protection
					this->OgPageProtection = Internal::GetPageProtection((void*)*this->PPFunction);

					// Copy the original function's data (cap size at 0x20)
					const auto DisasmFunctionSize = Internal::GetFunctionSize((std::uint8_t*)this->OgPFunction);
					const auto FunctionSize = DisasmFunctionSize > 0x20 ? 0x20 : DisasmFunctionSize;
					
					// Reserve & copy.
					this->OriginalFunction.resize(FunctionSize);
					std::memcpy(
						this->OriginalFunction.data(),
						(void*)this->OgPFunction,
						FunctionSize
					);

					this->SetupSuccess = true;
				}
			}
		}
	};

	// A list of imports which have been hoodinied. LOL.
	std::vector<HoodiniImport> HoodiniedImports;
	void* HoodiniAllocation = nullptr;
	size_t HoodiniAllocationSize = 0x00;

	// These are functions that have to be resolved so that
	// the callback can use them regardless of whether
	// they are protected by ImportHoodini (avoids stack overflow)
	typedef SIZE_T t_VirtualQuery(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
	t_VirtualQuery* fnVirtualQuery = nullptr;
	
	typedef BOOL t_VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
	t_VirtualProtect* fnVirtualProtect = nullptr;
	
	void HoodiniCallback(void* Import)
	{
		// Ensure to lock as we handle vectors which are considered
		// to be NOT thread safe.
		std::scoped_lock CallbackLock(ThreadLock);

		// Locate the import...
		HoodiniImport* LocatedImportObj = nullptr;
		for (auto& HoodiniedImport : HoodiniedImports)
		{
			if (HoodiniedImport.OgPFunction == (std::uint64_t)Import)
			{
				LocatedImportObj = &HoodiniedImport;
				break;
			}
		}

		if (LocatedImportObj)
		{
			// Now we need to check whether the fn has been patched,
			bool LocatedPatch = false;
			const auto IntegCheckSize = LocatedImportObj->OriginalFunction.size();
			const auto PIntegrityStart = (std::uint8_t*)LocatedImportObj->OgPFunction;
			for (std::uint32_t i = 0; i < IntegCheckSize; i++)
			{
				if (PIntegrityStart[i] != LocatedImportObj->OriginalFunction[i]) 
				{
					// Dump and report.
					LocatedPatch = true;
					break;
				}
			}

			if (LocatedPatch)
			{
				// Send a report of this first.
				{
					Reports::HoodiniCallbackReport PatchReport;
					
					// Set patch type
					PatchReport.PatchType = Reports::INL_HOOK;
				
					// Grab a function dump (avoid using API here, this may
					// be slower though)
					for (std::uint32_t i = 0; i < IntegCheckSize; i++)
						PatchReport.FunctionDump[i] = PIntegrityStart[i];

					Reports::ReportsList.push_back(PatchReport);
				}
				
				// Now handle it and change it back to it's original shit.
				{
					DWORD OldProtection, NewProtection = PAGE_EXECUTE_READWRITE;

					// Protect it.
					if (fnVirtualProtect(PIntegrityStart, IntegCheckSize, NewProtection, &OldProtection))
					{
						// Restore the bytes (not using API here as it's just easier, 
						// may not be as fast as memcpy or an equivalent)
						for (std::uint32_t i = 0; i < IntegCheckSize; i++)
							PIntegrityStart[i] = LocatedImportObj->OriginalFunction[i];

						// Restore protection
						fnVirtualProtect(PIntegrityStart, IntegCheckSize, OldProtection, &NewProtection);
					}
				}
			}

			// Now check protection!
			MEMORY_BASIC_INFORMATION PageMemInfo;
			if (fnVirtualQuery(PIntegrityStart, &PageMemInfo, sizeof(PageMemInfo)))
			{
				if (PageMemInfo.Protect != LocatedImportObj->OgPageProtection)
				{
					// Push a report for protection change
					{
						Reports::HoodiniCallbackReport PatchReport;

						// Set patch type
						PatchReport.PatchType = Reports::PROTECTION_HOOK;

						// Grab a function dump (avoid using API here, this may
						// be slower though)
						for (std::uint32_t i = 0; i < IntegCheckSize; i++)
							PatchReport.FunctionDump[i] = PIntegrityStart[i];

						Reports::ReportsList.push_back(PatchReport);
					}

					// Restore protection
					{
						DWORD OldProtection = PageMemInfo.Protect, NewProtection = LocatedImportObj->OgPageProtection;
						fnVirtualProtect(PIntegrityStart, IntegCheckSize, NewProtection, &OldProtection);
					}
				}
			}
		}
	}

	bool ActivateImportCallbacks()
	{
		const auto HoodiniedImportsCount = HoodiniedImports.size();
		if (!HoodiniedImportsCount || HoodiniAllocation)
			return false;
		
		/*
		* 
		* ASM EQUIVALENT:
		ShadowSpaceSize = 0x28
		ShadowSpace     = 0x00
		TrapFrameSize   = 0x60
		TrapFrame       = ShadowSpace + ShadowSpaceSize

		sub   rsp, ShadowSpaceSize + TrapFrameSize
		mov   qword ptr TrapFrame[rsp + 0x00], rcx
		mov   qword ptr TrapFrame[rsp + 0x08], rdx
		mov   qword ptr TrapFrame[rsp + 0x10], r8
		mov   qword ptr TrapFrame[rsp + 0x18], r9
		movups xmmword ptr TrapFrame[rsp + 0x20], xmm0
		movups xmmword ptr TrapFrame[rsp + 0x30], xmm1
		movups xmmword ptr TrapFrame[rsp + 0x40], xmm2
		movups xmmword ptr TrapFrame[rsp + 0x50], xmm3

		mov   rcx, 0xBABECAFE
		lea   rdx, TrapFrame[rsp]
		mov rax, 0xDEADBEEF
		call  rax

		mov   rcx, qword ptr TrapFrame[rsp + 0x00]
		mov   rdx, qword ptr TrapFrame[rsp + 0x08]
		mov   r8, qword ptr TrapFrame[rsp + 0x10]
		mov   r9, qword ptr TrapFrame[rsp + 0x18]
		movups xmm0, xmmword ptr TrapFrame[rsp + 0x20]
		movups xmm1, xmmword ptr TrapFrame[rsp + 0x30]
		movups xmm2, xmmword ptr TrapFrame[rsp + 0x40]
		movups xmm3, xmmword ptr TrapFrame[rsp + 0x50]

		mov   r10, 0xBABECAFE

		add   rsp, ShadowSpaceSize + TrapFrameSize
		jmp   r10

		*
		* INTEL ASM ASSEMBLED: 
		0:  48 81 ec 88 00 00 00    sub    rsp,0x88
		7:  48 89 4c 24 28          mov    QWORD PTR [rsp+0x28],rcx
		c:  48 89 54 24 30          mov    QWORD PTR [rsp+0x30],rdx
		11: 4c 89 44 24 38          mov    QWORD PTR [rsp+0x38],r8
		16: 4c 89 4c 24 40          mov    QWORD PTR [rsp+0x40],r9
		1b: 0f 11 44 24 48          movups XMMWORD PTR [rsp+0x48],xmm0
		20: 0f 11 4c 24 58          movups XMMWORD PTR [rsp+0x58],xmm1
		25: 0f 11 54 24 68          movups XMMWORD PTR [rsp+0x68],xmm2
		2a: 0f 11 5c 24 78          movups XMMWORD PTR [rsp+0x78],xmm3
		2f: 48 b9 fe ca be ba 00    movups rcx,0xbabecafe
		36: 00 00 00
		39: 48 8d 54 24 28          lea    rdx,[rsp+0x28]
		3e: 48 b8 ef be ad de 00    movabs rax,0xdeadbeef
		45: 00 00 00
		48: ff d0                   call   rax
		4a: 48 8b 4c 24 28          mov    rcx,QWORD PTR [rsp+0x28]
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
		83: 41 ff e2                jmp    r10


		Array literal:
		{ 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x89, 0x54, 0x24, 0x30, 0x4C, 0x89, 0x44, 0x24, 0x38, 0x4C, 0x89, 0x4C, 0x24, 0x40, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x0F, 0x11, 0x4C, 0x24, 0x58, 0x0F, 0x11, 0x54, 0x24, 0x68, 0x0F, 0x11, 0x5C, 0x24, 0x78, 0x48, 0xB9, 0xFE, 0xCA, 0xBE, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x8B, 0x54, 0x24, 0x30, 0x4C, 0x8B, 0x44, 0x24, 0x38, 0x4C, 0x8B, 0x4C, 0x24, 0x40, 0x0F, 0x10, 0x44, 0x24, 0x48, 0x0F, 0x10, 0x4C, 0x24, 0x58, 0x0F, 0x10, 0x54, 0x24, 0x68, 0x0F, 0x10, 0x5C, 0x24, 0x78, 0x49, 0xBA, 0xFE, 0xCA, 0xBE, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2 }		## Assembled with https://defuse.ca/
		*/

		const void* CallbackFunction = &HoodiniCallback;
		uint8_t SubCallbackStub[] = { 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x89, 0x54, 0x24, 0x30, 0x4C, 0x89, 0x44, 0x24, 0x38, 0x4C, 0x89, 0x4C, 0x24, 0x40, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x0F, 0x11, 0x4C, 0x24, 0x58, 0x0F, 0x11, 0x54, 0x24, 0x68, 0x0F, 0x11, 0x5C, 0x24, 0x78, 0x48, 0xB9, 0xFE, 0xCA, 0xBE, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x8B, 0x54, 0x24, 0x30, 0x4C, 0x8B, 0x44, 0x24, 0x38, 0x4C, 0x8B, 0x4C, 0x24, 0x40, 0x0F, 0x10, 0x44, 0x24, 0x48, 0x0F, 0x10, 0x4C, 0x24, 0x58, 0x0F, 0x10, 0x54, 0x24, 0x68, 0x0F, 0x10, 0x5C, 0x24, 0x78, 0x49, 0xBA, 0xFE, 0xCA, 0xBE, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2 };
		
		// Calculate how much size we need...
		HoodiniAllocationSize = HoodiniedImportsCount * sizeof(SubCallbackStub);

		if (HoodiniAllocation = VirtualAlloc(nullptr, HoodiniAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
		{
			for (std::uint32_t i = 0; i < HoodiniedImportsCount; i++)
			{
				const auto ToHoodiniImport = &HoodiniedImports[i];

				const auto SubAllocation = (std::uint64_t)HoodiniAllocation + (i * sizeof(SubCallbackStub));

				std::memcpy(
					(void*)SubAllocation,
					SubCallbackStub,
					sizeof(SubCallbackStub)
				);

				// Now write the addresses in...
				// 0xbabecafe addresses at 0x31 & 0x74 (original function addr)
				std::memcpy((void*)(SubAllocation + 0x31), ToHoodiniImport->PPFunction, 0x8);
				std::memcpy((void*)(SubAllocation + 0x74), ToHoodiniImport->PPFunction, 0x8);
				
				// 0xdeadbeef address at 0x40 (handler addr)
				std::memcpy((void*)(SubAllocation + 0x40), &CallbackFunction, 0x8);

				DWORD NewProt = PAGE_EXECUTE_READWRITE, OldProt = PAGE_EXECUTE_READ;
				VirtualProtect(ToHoodiniImport->PPFunction, 0x8, NewProt, &OldProt);
				*ToHoodiniImport->PPFunction = SubAllocation;
				VirtualProtect(ToHoodiniImport->PPFunction, 0x8, OldProt, &OldProt);
			}
		}
	}

	void ResolveCallbackAPI()
	{
		static const auto KernelBase = LoadLibraryA("KERNELBASE.dll");

		if (!fnVirtualQuery)
		{
			fnVirtualQuery = (t_VirtualQuery*)GetProcAddress(
				LoadLibraryA("KERNELBASE.dll"),
				"VirtualQuery"
			);
		}

		if (!fnVirtualProtect)
		{
			fnVirtualProtect = (t_VirtualProtect*)GetProcAddress(
				LoadLibraryA("KERNELBASE.dll"),
				"VirtualProtect"
			);
		}
	}

	bool Setup_AllImports(HMODULE TargetModule, std::vector<std::uint64_t> RefuseList)
	{
		// Ensure to resolve callback API to give
		// callback the ability to integrity check
		// without deadlock / stack overflow
		ResolveCallbackAPI();

		const auto Imports = Internal::FetchImports(
			(std::uint64_t)TargetModule
		);

		for (const auto& Import : Imports)
		{
			const auto OgFirstThunk = Import.first;
			const auto FirstThunk = Import.second;

			// Check whether this is present in the RefuseList.
			if (std::find(RefuseList.begin(), RefuseList.end(), FirstThunk->u1.Function) != RefuseList.end())
				continue;

			// Check if this fn has been parsed already
			bool AlreadyParsed = false;
			for (const auto& ExistingImport : HoodiniedImports)
			{
				if (*ExistingImport.PPFunction == FirstThunk->u1.Function)
				{
					AlreadyParsed = true;
					break;
				}
			}

			if (AlreadyParsed)
				continue;

			// Let's create it's object and then store it.
			const auto HoodiniedImport = HoodiniImport(
				(std::uint64_t)TargetModule,
				OgFirstThunk,
				FirstThunk
				);

			if (HoodiniedImport.SetupSuccess)
			{
				// Check for success and then whack this bitch in.
				HoodiniedImports.push_back(HoodiniedImport);
			}
		}

		return HoodiniedImports.size();
	}

	bool Setup_Specific(HMODULE TargetModule, std::vector<std::uint64_t> SpecificList)
	{
		// Ensure to resolve callback API to give
		// callback the ability to integrity check
		// without deadlock / stack overflow
		ResolveCallbackAPI();

		const auto Imports = Internal::FetchImports(
			(std::uint64_t)TargetModule
		);

		for (const auto& Import : Imports)
		{
			const auto OgFirstThunk = Import.first;
			const auto FirstThunk = Import.second;

			// Check whether this is present in the RefuseList.
			if (std::find(SpecificList.begin(), SpecificList.end(), FirstThunk->u1.Function) == SpecificList.end())
				continue;

			// Check if this fn has been parsed already
			bool AlreadyParsed = false;
			for (const auto& ExistingImport : HoodiniedImports)
			{
				if (*ExistingImport.PPFunction == FirstThunk->u1.Function)
				{
					AlreadyParsed = true;
					break;
				}
			}

			if (AlreadyParsed)
				continue;

			// Let's create it's object and then store it.
			const auto HoodiniedImport = HoodiniImport(
				(std::uint64_t)TargetModule,
				OgFirstThunk,
				FirstThunk
			);

			if (HoodiniedImport.SetupSuccess)
			{
				// Check for success and then whack this bitch in.
				HoodiniedImports.push_back(HoodiniedImport);
			}
		}

		return HoodiniedImports.size();
	}
}