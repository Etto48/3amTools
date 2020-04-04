#!/usr/bin/env python3
from unicorn import *
from stringcolor import *
from unicorn.x86_const import *
from subprocess import *
from pwn import *
import sys
import capstone

print(cs("╦  ┌─┐┌─┐┌─┐┬─┐╦ ╦┌┐┌┬┌─┐┌─┐┬─┐┌┐┌\n","cyan")+
      cs("║  ├─┤└─┐├┤ ├┬┘║ ║│││││  │ │├┬┘│││\n","magenta")+
      cs("╩═╝┴ ┴└─┘└─┘┴└─╚═╝┘└┘┴└─┘└─┘┴└─┘└┘\n","yellow")+
      cs("A unicorn-emulator interface by the_E","cyan"))


'''def read(name):
    with open(name,"rb") as f:
        return f.read()
'''
def fromHex(string):
    h=string
    if("x" in h):
        ret=int(h.split("x")[1],16)
    else:
        ret=int(h,16)
    return ret

fname=""
skipAddress=[]
breakAddress=[]
noCall=False


#terminal
def readCommand(duringExecution=False):
    prevCommand=False
    lastCommand=""
    while(True):
        if(prevCommand == False):
            tColor="magenta"
            if(duringExecution==True):
                tColor="red"
            print(cs("LU",tColor),end="")
            command = input(">").decode("utf-8")[:-1]
        else:
            command = lastCommand
            prevCommand = False
        if(command == "run" or command == "r"):
            if(duringExecution==False):
                runProcess()
            else:
                print("The program is already running...")
        if(command.split(" ")[0] == "skip" or command.split(" ")[0] == "sk"):
            for i in range(len(command.split(" "))-1):
                skipAddress.append(fromHex(command.split(" ")[i+1]))
        if(command == "continue" or command == "c"):
            if(duringExecution==True):
                break
            else:
                print("The program is not running now, try '(r)un' to start te simulation")
        if(command.split(" ")[0] == "break" or command.split(" ")[0] == "b"):
            for i in range(len(command.split(" "))-1):
                breakAddress.append(fromHex(command.split(" ")[i+1]))


        if(command == "quit" or command == "q"):
            exit(0)
        if(command==""):
            prevCommand = True
        else:
            lastCommand = command


#run each instruction
def disassemble(code, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
    for i in cs.disasm(code, addr):
        return i
def hook_code(mu, address, size,user_data):
    instruction=""
    for b in struct.unpack('<'+'B'*size,mu.mem_read(mu.reg_read(UC_X86_REG_RIP),size)):
        instruction+="%02x "%b
    
    color="green"
    status="    "
    if(address in skipAddress):
        color="darkGray"
        status="<sk>"
        mu.reg_write(UC_X86_REG_RIP,address+size)
    if(address in breakAddress):
        status="<br>"
   
    code = mu.mem_read(address, size)
    insn = disassemble(code, address)
    icol="white"
    if(status=="<sk>"):
        icol=color
    elif("{:s}".format(insn.mnemonic)=="mov"):
        icol="yellow"
    elif("{:s}".format(insn.mnemonic)=="call"):
        icol="red"
        if(noCall==True):
            color="darkGray"
            icol="drakGray"
            mu.reg_write(UC_X86_REG_RIP,address+size)
            status="<sk>"
    elif("{:s}".format(insn.mnemonic)=="ret"):
        icol="orange"
    elif("{:s}".format(insn.mnemonic)=="push" or "{:s}".format(insn.mnemonic)=="pop"):
        icol="cyan"
    print("RIP: {} {:#x}:\t{:s}".format(cs(status,"blue"),insn.address,instruction)+" "*(7-size)*3+cs("\t {:s}".format(insn.mnemonic),icol) +cs(" {:s}".format(insn.op_str),color))

    if(status=="<br>"):
        readCommand(duringExecution=True)



    
    
ENTRY=0
END=0


#WIP argvc=[]
manualAddress=False
fetchEntry="_start"
fetchExit="_fini"
#reading args from command line
if(len(sys.argv)>1):
    try:
        for i in range(len(sys.argv)-1):
            if(sys.argv[i+1]=="-f" or sys.argv[i+1]=="--file"):
                fname=sys.argv[i+2]
            if(sys.argv[i+1]=="--entry"):
                try:
                    ENTRY=fromHex(sys.argv[i+2])
                except:
                    fetchEntry=sys.argv[i+2]
            if(sys.argv[i+1]=="--exit"):
                try:
                    END=fromHex(sys.argv[i+2])
                except:
                    fetchExit=sys.argv[i+2]
            if(sys.argv[i+1]=="-s" or sys.argv[i+1]=="--skip"):#expected format a1,a2,a3,a4,...
                for a in sys.argv[i+2].split(","):
                    skipAddress.append(fromHex(a))
            if(sys.argv[i+1]=="-b" or sys.argv[i+1]=="--break"):#expected format a1,a2,a3,a4,...
                for a in sys.argv[i+2].split(","):
                    breakAddress.append(fromHex(a))
            if(sys.argv[i+1]=="--no-call"):
                noCall=True
     
    except IndexError as e:
        print("Wrong usage of arguments")
    
BASE = 0x555555554000

LIBC_ADDR = 0x7ffff79e4000
LD_ADDR = 0x7ffff7dd5000

STACK_ADDR = 0x0
STACK_SIZE = 1024*1024
#WIP ARGV_LOC = 0x300000

if(fname==""):
    fname = input("Executable: ")
    fname=fname.decode("utf-8").split("\n")[0]


try:
    if(ENTRY==0):
        pipe = Popen("nm {}| egrep '. {}$'".format(fname,fetchEntry), shell=True,
                stderr=STDOUT, stdout=PIPE,).stdout
        output = pipe.read()
        ENTRY=fromHex(output.decode("utf-8").split(" ")[0])

        print(("Detected {} symbol at 0x%x"%ENTRY).format(fetchEntry))
    else:
        print("Entry point manually set to 0x%x"%ENTRY)
    if(END==0):
        pipe = Popen("nm {}| egrep '. {}$'".format(fname,fetchExit), shell=True,
                stderr=STDOUT, stdout=PIPE).stdout
        output = pipe.read()
        END=fromHex(output.decode("utf-8").split(" ")[0])
    
        print("Detected end of program near 0x%x"%END)
    else:
        print("Exit address manually set to 0x%x"%END)
except ValueError as e:
    print("Can't find symbols")
    ENTRY=fromHex(input("Please enter the entry point: 0x").decode("utf-8"))
    END=fromHex(input("Please enter the end of program address: 0x").decode("utf-8"))
except IndexError as e:
    print("Binary '{}' not found...".format(fname))
    exit(-1)



ENTRY+=BASE
END+=BASE

mu = Uc(UC_ARCH_X86, UC_MODE_64)
      
mu.mem_map(BASE,1024*1024)

mu.mem_map(LIBC_ADDR,0x3F1000)
mu.mem_write(LIBC_ADDR,read('/lib/x86_64-linux-gnu/libc-2.27.so'))

mu.mem_map(LD_ADDR,1024*1024)
mu.mem_write(LIBC_ADDR,read('/lib/x86_64-linux-gnu/ld-2.27.so'))
#WIP mu.mem_map(ARGV_LOC,1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)  

mu.mem_write(BASE, read(fname))
print("File loaded @ 0x%x"%BASE)
mu.reg_write(UC_X86_REG_RSP,STACK_ADDR+STACK_SIZE -1)



mu.hook_add(UC_HOOK_CODE, hook_code)


def runProcess():
    try:
        mu.emu_start(ENTRY,END)
        rax = mu.reg_read(UC_X86_REG_RAX)
        print("return = 0x%x"% rax)
    except UcError as e:
        print("ERROR: {}".format(e))
        
readCommand(duringExecution=False)
