// The curated ASR rules the console exposes, in the exact GUID -> description
// mapping used by the server (internal/server/httpapi/ringfences.go). Keep
// these in sync — the description is what the console and the API agree on,
// and what Playwright selects by.
//
// Shared rather than duplicated: the ringfence detail page edits these and
// the device page reports them, and two copies would drift the moment a rule
// is added to the curated set.
export const ASR_RULES: { id: string; description: string }[] = [
  { id: "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", description: "Office applications creating child processes" },
  { id: "3B576869-A4EC-4529-8536-B80A7769E899", description: "Office applications creating executable content" },
  { id: "D3E037E1-3EB8-44C8-A917-57927947596D", description: "JS/VBScript launching downloaded executable content" },
  { id: "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", description: "Execution of potentially obfuscated scripts" },
  { id: "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", description: "Win32 API calls from Office macros" },
  { id: "D1E49AAC-8F56-4280-B9BA-993A6D77406C", description: "Process creation from PSExec and WMI" },
];

// asrDescription falls back to the raw GUID rather than rendering nothing, so
// a rule the server knows about but this build does not is still legible.
export function asrDescription(id: string): string {
  const match = ASR_RULES.find((r) => r.id.toLowerCase() === id.toLowerCase());
  return match ? match.description : id;
}
