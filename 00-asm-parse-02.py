#!/usr/bin/env python3

spec = {}
function = None
label_to_iblock = {}
iblock_to_label = {}
label_map1 = {}
label_map2 = {}

tricks = [
	[ "push REG1\npop REG2", "REG2 = REG1" ],
	[ "add REG1,REG2", "REG1 = REG1 + REG2" ],
]

def is_hex(text):
	for ch in text:
		if '0' <= ch and ch <= '9':
			continue
		if 'a' <= ch and ch <= 'f':
			continue
		if 'A' <= ch and ch <= 'F':
			continue
		return False
	return True

def is_dec(text):
	for ch in text:
		if '0' <= ch and ch <= '9':
			continue
		return False
	return True

# REG0, REG1, REG2, ...
def is_unknown_reg(text):
	text = text.strip()
	if text[:3] != 'REG':
		return false
	return is_dec(text[3:])

# MEM0, MEM1, MEM2, ...
def is_unknown_mem(text):
	text = text.strip()
	if text[:3] != 'MEM':
		return false
	return is_dec(text[3:])

def is_8bit_reg(text):
	text = text.strip()
	if text in 'al,ah,bl,bh,cl,ch,dl,dh'.split(','):
		return True
	return False

def is_16bit_reg(text):
	text = text.strip()
	if text in 'ax,bx,cx,dx,si,di,bp,sp,cs,ss,ds,es,fs,gs,ip,FLAGS'.split(','):
		return True
	return False

def is_32bit_reg(text):
	text = text.strip()
	if text in 'eax,ebx,ecx,edx,esi,edi,ebp,esp,eip,EFLAGS'.split(','):
		return True
	return False

def is_reg(text):
	if is_8bit_reg(text) or is_16bit_reg(text) or is_32bit_reg(text):
		return True
	if is_unknown_reg(text):
		return True
	return False

def get_mem_size(text):
	text = text.strip()
	if text[-1] != ']':
		return 0
	if text[:11] == 'dword ptr [':
		return 4
	if text[:10] == 'word ptr [':
		return 2
	if text[:10] == 'byte ptr [':
		return 1
	return 0

def get_mem_addr(text):
	i0 = text.find('[')
	i1 = text.find(']')
	if i0 != -1 and i1 != -1:
		return text[i0 + 1 : i1]
	return ''

def is_arg(text):
	if text[:5] == 'ARGV[' and text[-1] == ']':
		return True
	return False

def is_mem(text):
	if get_mem_size(text) > 0:
		return True
	if is_arg(text):
		return True

	return False

def get_size(text):
	if is_32bit_reg(text):
		return 4
	if is_16bit_reg(text):
		return 2
	if is_8bit_reg(text):
		return 1
	if is_mem(text):
		return get_mem_size(text)
	return -1

def load_spec(file, module_name):
	global spec
	with open(file, 'r') as fin:
		lines = fin.read().split('\n')
		for line in lines:
			i0 = line.find('#')
			if i0 != -1:
				line = line[:i0]
			i1 = line.find(';')
			if i1 != -1:
				line = line[:i1]
			line = line.replace('-stub ', '')
			i2 = line.find('stdcall')
			if i2 == -1:
				i5 = line.find(', ')
				if i5 != -1:
					items = line.split(',')
					func_name = items[0].strip()
					num_params = items[1].strip()
					spec[module_name + '!' + func_name] = {'function': func_name, 'module': module_name, 'num_params': num_params}
				continue
			import re
			line = re.sub('\\bstdcall\\b', '', line)
			line = line.replace('  ', '')
			body = line[i2-1:]
			i3 = body.find('(')
			i4 = body.find(')')
			if i3 == -1 or i4 == -1:
				continue
			func_name = body[:i3].strip()
			params = body[i3+1:i4].split(' ')
			if len(params) == 1 and params[0] == '':
				params = []
			spec[module_name + '!' + func_name] = {'function': func_name, 'module': module_name, 'num_params': len(params), 'params': params}

def asm_to_item(addr, hex, ope, operands):
	for i in range(0, len(operands)):
		operand = operands[i]
		i0 = operand.find('[')
		i1 = operand.find(']')
		if i0 != -1 and i1 != -1:
			s0 = operand[0:i0+1]
			s1 = operand[i0+1:i1]
			s2 = operand[i1:]
			if s1.find(' ') != -1:
				s1 = s1.split(' ')[0]
			t = s0 + s1 + s2
			operands[i] = t
	if ope == '=':
		return ['=', operands[0], operands[1]]
	else:
		type = 'stack'
		if ope == 'call':
			type = 'call'
			if operands[0][:11] == 'dword ptr [':
				operands = [get_mem_addr(operands[0])]
			else:
				operands = [operands[0].split(' ')[0]]
		elif ope == 'jmp':
			type = 'jmp'
			if operands[0][:11] == 'dword ptr [':
				operands = [get_mem_addr(operands[0])]
			else:
				operands = [operands[0].split(' ')[0]]
		elif ope[0] == 'j':
			type = 'jcc'
			if operands[0][:11] == 'dword ptr [':
				operands = [get_mem_addr(operands[0])]
			else:
				operands = [operands[0].split(' ')[0]]
		elif ope == 'ret':
			type = 'ret'
		elif ope == 'push' or ope == 'pop':
			type = 'stack'
		elif ope == 'enter' or ope == 'leave':
			type = 'stack'
		else:
			for op in operands:
				if op == 'esp' or op == 'ebp':
					type = 'stack'
					break
		ary = [type, ope]
		ary.extend(operands)
		return ary
	return []

def text_to_data(text):
	data = []
	lines = text.split('\n')
	for line in lines:
		line = line.strip()
		if line == '' or line == '---':
			continue
		if line[:3] == 'kd>':
			continue
		if line[:11] == 'Breakpoint ':
			continue
		while True:
			new_line = line.replace('  ', ' ')
			if line == new_line:
				break
			line = new_line
		ope = ''
		operands = []
		ieq = line.find(' = ')
		addr = ''
		hex = ''
		if ieq != -1:
			s0 = line[:ieq].strip()
			s1 = line[ieq + 3:].strip()
			ope = '='
			operands = [s0, s1]
		else:
			items = line.split(' ')
			if (len(items) == 0):
				continue
			field0 = items[0].strip()
			if (len(items) == 1):
				if field0[-1] == ':':
					data.append(['label', field0[0:-1]])
					continue
			field1 = ''
			if len(items) >= 2:
				field1 = items[1].strip()
			if is_hex(field0) and is_hex(field1):
				addr = field0
				hex = field1
				items = items[2:]
			operands = ' '.join(items[1:]).split(',')
			ope = items[0]
		ary = asm_to_item(addr, hex, ope, operands)
		if (len(ary) > 0):
			data.append(ary)
			continue
		print('ERROR: invalid line: ' + line)
	return data

def file_to_data(file):
	data = []
	with open(file, 'r') as fin:
		text = fin.read()
		data = text_to_data(text)
	return data

def simplify_labels(data):
	global label_map1
	global label_map2
	number = 0
	global function
	for item in data:
		if item[0] == 'label':
			i0 = item[1].find('+')
			if (i0 == -1):
				function = item[1]
				continue
			label_map1[item[1]] = 'label' + str(number)
			label_map2['label' + str(number)] = item[1]
			number += 1
	if function != None:
		label_map1[function] = function
		label_map2[function] = function
	print('--- label_map1 ---')
	print(label_map1)
	print('--- label_map2 ---')
	print(label_map2)
	new_data = []
	for item in data:
		if item[0] == 'label':
			item[1] = label_map1[item[1]]
		elif item[0] == 'jmp':
			item[2] = label_map1[item[2]]
		elif item[0] == 'jcc':
			item[2] = label_map1[item[2]]
		new_data.append(item)
	return new_data

def split_basic_blocks(data):
	new_data = []
	ary = []
	iblock = 0;
	first = True
	for item in data:
		if item[0] == 'label':
			global iblock_to_label
			global label_to_iblock
			global label_map1
			label_to_iblock[item[1]] = iblock
			iblock_to_label[iblock] = item[1]
			if first:
				first = False
				ary.append(item)
				iblock += 1
				continue
			new_data.append(ary)
			iblock += 1
			ary = []
			ary.append(item)
			continue
		ary.append(item)
	new_data.append(ary)
	print('--- iblock_to_label ---')
	print(iblock_to_label)
	print('--- label_to_iblock ---')
	print(label_to_iblock)
	return new_data

def optimize_data_0(data):
	new_data = []
	pushing = []
	for item in data:
		if item[1] == 'mov':
			if item[2] == item[3]:
				continue # nop
			new_data.append(['=', item[2], item[3]])
			continue
		elif item[1] == 'xor':
			if item[2] == item[3]:
				new_data.append(['=', item[2], '0'])
				continue
			new_data.append(['^=', item[2], item[3]])
			continue
		elif item[1] == 'lea':
			new_data.append(['=', item[2], get_mem_addr(item[3])])
			continue
		elif item[1] == 'add':
			if item[2] == item[3]:
				new_data.append(['*=', item[2], '2'])
				continue
			new_data.append(['+=', item[2], item[3]])
			continue
		elif item[1] == 'sub':
			new_data.append(['-=', item[2], item[3]])
			continue
		elif item[1] == 'mul':
			new_data.append(['*=', item[2], item[3]])
			continue
		elif item[1] == 'and':
			if item[2] == item[3]:
				new_data.append(['=', 'ZF', '(' + item[2] + ' == 0)'])
				continue
			new_data.append(['&=', item[2], item[3]])
			continue
		elif item[1] == 'xor':
			if item[2] == item[3]:
				new_data.append(['=', item[2], '0'])
				continue
			new_data.append(['^=', item[2], item[3]])
			continue
		new_data.append(item)
	return new_data

def get_block_type(block):
	if block[-1][0] == 'ret':
		return 'ret'
	if block[-1][0] == 'jmp':
		return 'jmp'
	if block[-1][0] == 'jcc':
		return 'jcc'
	return 'join'

def make_blocks_dict(data):
	new_data = {}
	iblock = 0
	for i in range(0, len(data)):
		block = data[i];
		type = get_block_type(block)
		new_data[iblock] = {'iblock': iblock, 'data': block, 'type': type }
		go_out = []
		if type == 'jmp':
			go_out.append(label_to_iblock[block[-1][2]])
		elif type == 'jcc':
			go_out.append(label_to_iblock[block[-1][2]])
			go_out.append(iblock + 1)
		elif type == 'join':
			go_out.append(iblock + 1)
		new_data[iblock]['go_out'] = go_out
		iblock += 1
	return new_data

def stage1(data):
	data = optimize_data_0(data)
	data = simplify_labels(data)
	data = split_basic_blocks(data)
	data = make_blocks_dict(data)
	return data
def stage2(data):
	return data
def stage3(data):
	return data

def item_to_text(item):
	if item[0] == 'label':
		return item[1] + ':'
	elif item[0] == '=':
		return item[1] + ' = ' + item[2] + ';'
	elif item[0] == 'jmp':
		return 'goto ' + item[2] + ';'
	elif item[0] == 'stack':
		if item[1] == 'push':
			return 'Push ' + item[2] + ';'
		elif item[1] == 'pop':
			return 'Pop ' + item[2] + ';'
		else:
			return item
	elif item[0] == 'ret':
		return 'return eax or void;'
	else:
		return str(item)

def data_to_text(data):
	text = ''
	for item in data:
		if text != '':
			text += '\n';
		text += item_to_text(item)
	return text;

def print_data(data):
	text = ''
	if function != None:
		text += 'def ' + function + '('
		num_params = 0
		if function in spec:
			num_params = spec[function]['num_params']
		params = ''
		for i in range(0, num_params):
			if params != '':
				params += ', '
			params += 'ARGV[' + str(num_params) + ']'
		if num_params == 0:
			params = 'void'
		text += params + ")\n"
		text += "{\n"
	for key, value in data.items():
		text += "\n"
		text += "// Block #" + str(key) + \
		        ' (type:' + value['type'] + \
		        ", go_out:" + str(value['go_out']) + \
		        ")\n"
		for item in value['data']:
			text += str(item_to_text(item)) + "\n"
	if function != None:
		text += "\n}\n"
	print(text)

def unittest():
	data = text_to_data('A = 1')
	assert data_to_text(data) == 'A = 1;'
	data = text_to_data('push eax')
	assert data_to_text(data) == 'Push eax;'
	data = text_to_data('pop eax')
	assert data_to_text(data) == 'Pop eax;'
	data = text_to_data('push eax\npop ebx')
	assert data_to_text(data) == 'Push eax;\nPop ebx;'
	data = text_to_data('push eax\npop ebx')
	data = optimize_data_0(data)
	print(data_to_text(data))
	print("unittest() ok")

def main(argv):
	unittest()
	print('--- spec ---')
	load_spec("user32.spec", "user32")
	load_spec("kernel32.spec", "kernel32")
	load_spec("win32k.spec", "win32k")
	load_spec("imm32.spec", "IMM32")
	load_spec("ntdll.spec", "ntdll")
	#print(spec)
	#print('---')
	data = file_to_data(argv[1])
	data = stage1(data)
	data = stage2(data)
	data = stage3(data)
	print('--- data ---')
	print(data)
	print('--- print_data ---')
	print_data(data)

import sys
main(sys.argv)
