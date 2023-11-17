#include <iostream>
#include <windows.h>
#include <vector>

namespace ImportHoodini
{
	namespace Reports
	{
		enum HoodiniPatchType : std::int32_t
		{
			NO_HOOK = 0,

			// Checks for a change in protection, please note:
			// all imports SHOULD point to an RX page which
			// lies in a .text section of a legit module.
			// This patch type will be set even if the protection
			// is changed from RX to RWX (no hook detected but
			// patch present).
			PROTECTION_HOOK,

			// Inline hook will check for any patches.
			// Inline hook will ALSO catch a 0xCC (trap to debugger) inst patch
			// which is really a sign of a VEH hook.
			INL_HOOK
		};

		typedef struct _HoodiniCallbackReport
		{
			// Not actually used but included in the case
			// of the user not wanting debug messages
			// for anti-debug reasons.
			HoodiniPatchType PatchType;

			// Function dump (will show patches if there
			// are any)
			char FunctionDump[0x20];
		} HoodiniCallbackReport, * PHoodiniCallbackReport;

		std::vector<HoodiniCallbackReport> GetReports();
	};

	// Activate (call after either setup)
	bool ActivateImportCallbacks();

	// Setup options:
	bool Setup_AllImports(HMODULE TargetModule = GetModuleHandleA(NULL), std::vector<std::uint64_t> RefuseList = {});
	bool Setup_Specific(HMODULE TargetModule = GetModuleHandleA(NULL), std::vector<std::uint64_t> SpecificList = {});
}