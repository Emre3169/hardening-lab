-- Create the ubuntu-lab VM in UTM (QEMU, aarch64, hardware-accelerated).
-- Run: osascript utm/create-ubuntu-lab.applescript
-- Sizes: memory and guest size are in MiB (see `sdef /Applications/UTM.app`).

set vmName to "ubuntu-lab"
set isoPath to (POSIX path of (path to home folder)) & "Developer/iso/ubuntu-24.04.5-live-server-arm64.iso"

-- Fail early if the ISO is missing rather than creating a VM with no boot media.
try
	set isoFile to POSIX file isoPath as alias
on error
	error "ISO not found: " & isoPath
end try

tell application "UTM"
	-- Refuse to create a duplicate.
	if (exists (first virtual machine whose name is vmName)) then
		error "A VM named " & vmName & " already exists; delete or rename it first."
	end if

	set vm to make new virtual machine with properties {backend:qemu, configuration:{name:vmName, architecture:"aarch64", memory:6144, cpu cores:4, hypervisor:true, uefi:true, drives:{{removable:true, source:isoFile}, {guest size:40960}}, network interfaces:{{index:0, mode:shared}}}}

	return "Created " & (name of vm) & " (id " & (id of vm) & ")"
end tell
