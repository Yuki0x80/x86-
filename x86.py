# -*- coding: utf-8 -*-
import fileinput
import re
import sys
import time
from ctypes import *
from struct import *

free   = cdll.msvcrt.free
printf = cdll.msvcrt.printf

def malloc(size):
    malloc = cdll.msvcrt.malloc
    malloc.restype = POINTER(ARRAY(c_ubyte, size))
    return malloc(size)[0]

REGISTERS_COUNT=0
register=["EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"]
registers={"EAX":0, "ECX":0, "EDX":0, "EBX":0, "ESP":0, "EBP":0, "ESI":0, "EDI":0}# "REGISTERS_COUNT":0}

class Emulator:
	def __init__(self):
		self.memory=0
		self.eip=0
		self.memory=0

	def create_emu(self,size,eip,esp):
		self.memory = malloc(size)
		self.eip = eip
		registers["ESP"] = esp
		
	def destroy_emu(self):
		free(self.memory)
    	
instructions=[0]*256
def parse_modrm(emu,modrm):
	code = get_code8(emu, 0)
	modrm.mod = ((code & 0xC0) >> 6)
	modrm.opecode = ((code & 0x38) >> 3)
	modrm.reg_index=modrm.opecode
	modrm.rm = code & 0x07
	emu.eip += 1

	if modrm.mod != 3 and modrm.rm == 4:
		modrm.sib = get_code8(emu, 0)
		emu.eip += 1

	if (modrm.mod == 0 and modrm.rm == 5) or (modrm.mod == 2):
		modrm.disp32 = get_sign_code32(emu, 0)
		emu.eip += 4
	elif modrm.mod == 1:
		modrm.disp8 = get_sign_code8(emu, 0)
		emu.eip += 1

def get_code32(emu,index):
    ret = 0
    for i in range(0,4):
        ret |= get_code8(emu, index + i) << (i * 8)
    return ret

def get_sign_code32(emu,index):
	return get_code32(emu, index)

def get_sign_code8(emu,index):
    return emu.memory[emu.eip + index]

def get_rm32(emu,modrm):
	if modrm.mod == 3 :
		return get_register32(emu, modrm.rm)
	else: 
		address = calc_memory_address(emu, modrm)
		return get_memory32(emu, address)

def get_register32(emu,index):
	return registers[register[index]]

def get_memory8(emu,address):
	return emu.memory[address]

def get_memory32(emu,address):
	ret=0
	for i in range(0,4):
		ret |= get_memory8(emu, address + i) << (8 * i)
	return ret

def get_r32(emu,modrm):
	 return get_register32(emu, modrm.reg_index)

def calc_memory_address(emu,modrm):
	if modrm.mod == 0:
		if modrm.rm == 4:
			printf("not implemented ModRM mod = 0, rm = 4\n")
			exit(0)
		elif modrm.rm == 5:
			return modrm.disp32
		else: 
			return get_register32(emu, modrm.rm);
	elif modrm.mod == 1:
		if modrm.rm == 4:
			printf("not implemented ModRM mod = 1, rm = 4\n")
			exit(0)
		else:
			return get_register32(emu, modrm.rm) + modrm.disp8
	elif modrm.mod == 2:
		if modrm.rm == 4:
			printf("not implemented ModRM mod = 2, rm = 4\n")
			exit(0)
		else:
			return get_register32(emu, modrm.rm) + modrm.disp32
	else: 
		printf("not implemented ModRM mod = 3\n")
		exit(0)

def set_r32(emu,modrm,value):
	set_register32(emu, modrm.reg_index,value)

def set_register32(emu,index,value):
	registers[register[index]]=value

def set_rm32(emu,modrm,value):
	if modrm.mod == 3:
		set_register32(emu, modrm.rm, value)
	else:
		address = calc_memory_address(emu, modrm)
		set_memory32(emu, address, value)

def sub_rm32_imm8(emu,modrm):
	rm32 = get_rm32(emu, modrm)
	imm8 = get_sign_code8(emu, 0)
	emu.eip += 1
	set_rm32(emu, modrm, rm32 - imm8)

def add_rm32_r32(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu, modrm)
	r32 = get_r32(emu, modrm)
	rm32 = get_rm32(emu, modrm)
	set_rm32(emu, modrm, rm32 + r32)

def mov_r32_imm32(emu):
	reg = get_code8(emu, 0) - 0xB8
	value = get_code32(emu, 1)
	set_register32(emu, reg, value)
	emu.eip += 5

def mov_r32_rm32(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu,modrm)
	rm32 = get_rm32(emu,modrm)
	set_r32(emu, modrm, rm32)

def inc_rm32(emu,modrm):
	value = get_rm32(emu, modrm)
	set_rm32(emu, modrm, value + 1)


def code_ff(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu,modrm)
	if modrm.opecode == 0:
		inc_rm32(emu,modrm)
	else:
		print "not implemented: FF /%d\n" % modrm.opecode
		exit(1)

def short_jump(emu):
	diff = get_sign_code8(emu, 1)
	emu.eip += (diff + 2)

def near_jump(emu):
	diff = get_sign_code32(emu, 1)
	emu.eip += (diff + 5)

def mov_rm32_imm32(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu, modrm)
	value = get_code32(emu, 0)
	emu.eip += 4
	set_rm32(emu, modrm, value)

class ModRM:
	def __init__(self):
		self.opecode=0
		self.mod=0
		self.rm=0
		self.sib=0
		self.disp8=0
		self.disp32=0
		self.reg_index=0

def code_83(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu,modrm)

	if modrm.opecode == 5:
		sub_rm32_imm8(emu,modrm)
	else:
		printf("not implemented: 83 /%d\n", modrm.opecode);
		exit(1)

def mov_rm32_r32(emu):
	emu.eip += 1
	modrm=ModRM()
	parse_modrm(emu,modrm)
	r32 = get_r32(emu, modrm)
	set_rm32(emu, modrm, r32)

def set_memory8(emu,address,value):
	emu.memory[address] = value & 0xFF

def set_memory32(emu,address,value):
	for i in range(0,4):
		set_memory8(emu, address + i, value >> (i * 8))
def init_instructions():
	instructions[0x01] = add_rm32_r32
	instructions[0x83] = code_83
	instructions[0x89] = mov_rm32_r32
	instructions[0x8B] = mov_r32_rm32
	for i in range(0,8): 
		instructions[0xB8 + i] = mov_r32_imm32;
	instructions[0xC7] = mov_rm32_imm32
	instructions[0xE9] = near_jump
	instructions[0xEB] = short_jump
	instructions[0xFF] = code_ff

def read_binary(emu,file):
	f = open(file,"rb")
	for i in range(0,512):
		try: emu.memory[0x7c00|i]=unpack('B', f.read(1))[0]
		except: emu.memory[0x7c00|i]=0
	f.close()
	#print "hey",emu.memory[0x7c00]

def get_code8(emu,index):
	return emu.memory[emu.eip + index]

def dump_registers(emu):
	for k, v in registers.items():
		print k, hex(v)

MEMORY_SIZE = 1024 * 1024
if __name__ == "__main__":
	argvs = sys.argv 
	argc = len(argvs) 
	if (argc != 2):  
		quit()

	init_instructions()
	emu=Emulator()
	emu.create_emu(MEMORY_SIZE, 0x7c00, 0x7c00)
	read_binary(emu,argvs[1])
	while emu.eip < MEMORY_SIZE:
		code = get_code8(emu, 0);
		print "EIP = ",hex(emu.eip), "Code = ",hex(code)
        #if instructions[code] == NULL
        #    print "Not Implemented: %x\n" % code
        #    break
		instructions[code](emu)
		if (emu.eip == 0):
			print "end of program."
			break
	dump_registers(emu)
	emu.destroy_emu()