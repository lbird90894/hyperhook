# 1. Introduction
Since Windows x64, the kernel is protected by KPP(Kernel Patch Protection), making hooking impossible.
This project is a WDM static library that hooks native functions in the kernel, bypassing KPP through virtualization.
I haven't analyzed KPP closely, but it generally works like this:  
"KPP compares the static information about native functions in the kernel and the code of native functions in memory at random times,
and generates a BSOD if they are different."  

Ideas for bypassing KPP through virtualization are as follows:
1. Virtualize memory through EPT.
2. After patching the code in the function to be hooked, set the page permission to execute only.
3. When calling the function, the hooked function is called.
4. If KPP attempts to read the memory of the hooked function in guest mode, 
   the host mode switches the hooked page back to the original page and changes the page permission to read-only.
5. KPP reads the original page that is the result of the host's handling.  
(Host mode means VMX root mode, and guest mode means VMX Non-root mode.)


This library includes the following:

* A 1-byte(int3) patch is used instead of a 5-byte patch, as the latter may cause synchronization issues.  
   This approach hooks by utilizing interrupt handling instead of trampolines.
* The TLB flush for page swapping in host mode is processed per individual core.  
   The page status management depends on individual cores, but it does not affect overall functionality.  
   (It might be hard to understand, so think carefully about it.)
* Since the concept of IRQL cannot be used in host mode, I implemented spinlock and logger necessary for logging.  
   (Only some formats such as %d, %llx, and %s are supported.)
* The hypervisor’s cache policy remains the same as the cache policy before the hypervisor was loaded.(MTRR, PAT...)
* EPT paging uses 2Mb pages, but when hooking, the page is split into 4Kb. When unhooking, the splitted 4Kb pages are merged back into 2Mb.
* Nested virtualization with other hypervisors like Hyper-V is not considered.


# 2. Environment
* CPU: Intel cpu that supports virtualization
* Memory: 512Gb or less
* OS: Windows 10 or higher(only x64 supported)


# 3. Configuration
* Hypervisor library (hyperhook.lib)
* Test driver for linking the hypervisor library(test.sys)
* Driver signature files to bypass KMCI(used only in Test B)


# 4. Test
The test consists of independent A and B.  
If you want to check kernel hooking through the hypervisor, perform Test A.  
If you want to verify kernel hooking through the hypervisor and bypass KPP, perform test B.

## 4.1. Test Environment
The environment that I tested on is as follows:
* vmware 15.5.7("Settings -> Hardware -> Processors -> Virtualize Intel VT-x/EPT or AMD-V/RVI" check)
* Guest OS: Windows 10 22h2(19041)

If you want to test on another version of Windows, check that the prologue of the NtCreateFile function to be hooked is as follows.  
**sub rsp,88h**  
**xor eax,eax**  
**mov qword ptr [rsp+78h], rax**

## 4.2. Log Configuration
To configure the log, run the log.reg file. The contents below provide a detailed explanation of the log.
* LogType: Determines whether to print to the kernel debugger or write to a file.  
1: Print to kernel debugger, 2: Write to file, 3: Print to kernel debugger and write to file

* LogLevel: Filters the logs to be output.  
1: Only error messages are output, 2: Warning messages are also output, 3: No filtering

* LogPath: Specifies the file path where the log file will be created.


## 4.3. Test A
After executing the log.reg file in Windows in a test mode environment, run the test.sys driver.  
You can check the log through C:\HKlog.txt, windbg + VirtualKD, dbgview64, etc.

The expected results are as follows:
1. The NtCreateFile function is hooked to print the file path.
2. The OriginTest function is hooked, and the first byte of the function prologue is not 0xCC.  
(The first byte of the OriginTest function is patched to 0xCC, but if the memory is accessed with read permission, 
the host handles this and reads the original memory before hooking.)


## 4.4. Test B
KPP may be disabled in Windows in a test mode environment. Accordingly, to directly verify KPP bypass, it must be tested in normal mode.
At this time, since the test driver does not have an HLK/HCK signature, it cannot be loaded by KMCI.
However, I explain below how to change KMCI's policy to load self-signed drivers.

Host OS
1. "Settings -> Options -> Advanced -> UEFI -> Enable secure boot" check
2. Move to the folder where the vmx file of the guest OS exists.
3. Copy PK_Cert.cer to that folder.
4. Delete the .nvram file.
5. Add the following content to the .vmx file.
uefi.allowAuthBypass = "TRUE"
uefi.secureBoot.PKDefault.file0 = "PK_Cert.cer"
6. Boot the guest OS.

Guest OS
1. Place the test folder in an appropriate location.
2. Run SetBootPolicy.bat.(Several reboots may occur.)
3. Sign the test.sys driver through SignDriver.bat.
4. After executing the log.reg file, run test.sys through StartDriver.bat.
   (You can check the log through C:\HKlog.txt, windbg + VirtualKD, dbgview64, etc.)


The expected results are as follows:
1. The NtCreateFile function is hooked to print the file path.
2. The OriginTest function is hooked, and the first byte of the function prologue is not 0xCC.  
(The first byte of the OriginTest function is patched to 0xCC, but if the memory is accessed with read permission, 
the host handles this and reads the original memory before hooking.)
3. Over time, KPP reads the memory of the NtCreateFile function, and the hypervisor handles it correctly, preventing a BSOD caused by KPP.  
   In my case, based on log analysis, KPP checked the integrity of the NtCreateFile function every 4 hours.

Optional
1. If you want to check whether the general kernel hooking method causes BSOD by KPP, run KppCheck.sys alone.  
   A BSOD(CRITICAL_STRUCTURE_CORRUPTION) will probably occur within a day.
2. If you want to create SiPolicy.xml yourself, use the attached WDACWizard.
3. If you want to create certificates yourself, check the reference below.

Please contact me if you have any questions or find bugs.  
(I am Korean, so I would appreciate it if you could ask your question in Korean or English.)

# 5. Reference
Hypervisor Related  
https://github.com/ionescu007/SimpleVisor
https://github.com/SinaKarvandi/Hypervisor-From-Scratch
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

Driver Signature Related  
https://github.com/HyperSine/Windows10-CustomKernelSigners
https://github.com/valinet/ssde
https://www.geoffchappell.com/notes/windows/license/customkernelsigners.htm
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/slmem/productpolicy.htm
 

# 6. License
	MIT License

	Copyright (c) 2024 lbird90894

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
