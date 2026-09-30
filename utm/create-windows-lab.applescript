-- Create the windows-lab VM in UTM (QEMU, aarch64, Windows 11 ARM64).
-- Run: osascript utm/create-windows-lab.applescript
-- Sizes: memory and guest size are in MiB (see `sdef /Applications/UTM.app`).
--
-- PLACEHOLDER: set isoPath to your Windows 11 ARM64 ISO before running.
-- Not configurable from the scripting API; check in the UTM GUI afterwards:
--   * TPM 2.0 (QEMU > "UEFI Boot" + "TPM 2.0 Device") — Windows 11 setup requires it.
--   * Attach UTM's SPICE/VirtIO guest tools ISO after install for drivers.

set vmName to "windows-lab"
set isoPath to (POSIX path of (path to home folder)) & "Developer/iso/REPLACE-ME-Win11_ARM64.iso"

try
	set isoFile to POSIX file isoPath as alias
on error
	error "ISO not found: " & isoPath & " (edit isoPath in this script)"
end try

tell application "UTM"
	if (exists (first virtual machine whose name is vmName)) then
		error "A VM named " & vmName & " already exists; delete or rename it first."
	end if

	set vm to make new virtual machine with properties {backend:qemu, configuration:{name:vmName, architecture:"aarch64", memory:4096, hypervisor:true, uefi:true, drives:{{removable:true, interface:USB, source:isoFile}, {interface:NVMe, guest size:65536}}, network interfaces:{{index:0, mode:shared}}}}

	return "Created " & (name of vm) & " (id " & (id of vm) & ")"
end tell
