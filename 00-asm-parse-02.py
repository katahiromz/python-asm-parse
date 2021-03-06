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
		return False
	return is_dec(text[3:])

# MEM0, MEM1, MEM2, ...
def is_unknown_mem(text):
	text = text.strip()
	if text[:3] != 'MEM':
		return False
	return is_dec(text[3:])

# X0, X1, X2, ...
def is_unknown_var(text):
	text = text.strip()
	if text[:1] != 'X':
		return False
	return is_dec(text[1:])

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

def is_reg(text, unknown_ok = False):
	if is_8bit_reg(text) or is_16bit_reg(text) or is_32bit_reg(text):
		return True
	if unknown_ok and is_unknown_reg(text):
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

def is_mem(text, unknown_ok = False):
	if get_mem_size(text) > 0:
		return True
	if is_arg(text):
		return True
	if unknown_ok and (is_unknown_mem(text) or is_unknown_var(text)):
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

def is_unknown(op):
	if is_unknown_mem(op) or is_unknown_reg(op) or is_unknown_var(op):
		return True
	return False

def operand_match(replace_dict, op0, op1):
	if op0 == op1:
		return True
	if is_unknown(op0) and not(is_unknown(op1)):
		if is_reg(op0, True) and is_reg(op1, True):
			replace_dict[op0] = op1
			return True
		if is_mem(op0, True) and is_mem(op1, True):
			replace_dict[op0] = op1
			return True
	if not(is_unknown(op0)) and is_unknown(op1):
		if is_reg(op0, True) and is_reg(op1, True):
			replace_dict[op1] = op0
			return True
		if is_mem(op0, True) and is_mem(op1, True):
			replace_dict[op1] = op0
			return True
	return False

def asm_match(replace_dict, asm0, asm1):
	type0 = asm0[0]
	type1 = asm1[0]
	if type0 != type1:
		return False
	op0 = asm0[1]
	op1 = asm1[1]
	if op0 != op1:
		return False
	operands0 = asm0[2:]
	operands1 = asm1[2:]
	if len(operands0) != len(operands1):
		return False
	for i in range(0, len(operands0)):
		op0 = operands0[i]
		op1 = operands1[i]
		if not(operand_match(replace_dict, op0, op1)):
			return False
	return True

def code_match(replace_dict, code0, code1):
	if len(code0) != len(code1):
		return False
	for i in range(0, len(code0)):
		if not(asm_match(replace_dict, code0[i], code1[i])):
			return False
	return True

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

def parse_asm(addr, hex, ope, operands):
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
		asm = [type, ope]
		asm.extend(operands)
		return asm
	return []

def text_to_code(text):
	code = []
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
					code.append(['label', field0[0:-1]])
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
		asm = parse_asm(addr, hex, ope, operands)
		if (len(asm) > 0):
			code.append(asm)
			continue
		print('ERROR: invalid line: ' + line)
	return code

def file_to_code(file):
	code = []
	with open(file, 'r') as fin:
		text = fin.read()
		code = text_to_code(text)
	return code

def simplify_labels(code):
	label_map1 = {}
	label_map2 = {}
	number = 0
	global function
	for item in code:
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
	new_code = []
	for item in code:
		if item[0] == 'label':
			item[1] = label_map1[item[1]]
		elif item[0] == 'jmp':
			item[2] = label_map1[item[2]]
		elif item[0] == 'jcc':
			item[2] = label_map1[item[2]]
		new_code.append(item)
	return label_map1, label_map2, new_code

def split_to_blocks(code):
	blocks = []
	block_code = []
	iblock = 0;
	first = True
	label_to_iblock = {}
	iblock_to_label = {}
	for item in code:
		if item[0] == 'label':
			global label_map1
			label = item[1]
			label_to_iblock[label] = iblock
			iblock_to_label[iblock] = label
			if first:
				first = False
				block_code.append(item)
				iblock += 1
				continue
			blocks.append({ 'code': block_code, 'iblock':iblock })
			iblock += 1
			block_code = [item]
			continue
		block_code.append(item)
	blocks.append({ 'code': block_code, 'iblock':iblock })
	for block in blocks:
		code = block['code']
		if code[0][0] == 'label':
			label = code[0][1]
			block['label'] = label
	return label_to_iblock, iblock_to_label, blocks

def optimize_code(code):
	new_list = []
	for item in code:
		if item[1] == 'mov':
			if item[2] == item[3]:
				continue # nop
			new_list.append(['=', item[2], item[3]])
			continue
		elif item[1] == 'xor':
			if item[2] == item[3]:
				new_list.append(['=', item[2], '0'])
				continue
			new_list.append(['^=', item[2], item[3]])
			continue
		elif item[1] == 'lea':
			new_list.append(['=', item[2], '(' + get_mem_addr(item[3]) + ')'])
			continue
		elif item[1] == 'add':
			if item[2] == item[3]:
				new_list.append(['*=', item[2], '2'])
				continue
			new_list.append(['+=', item[2], item[3]])
			continue
		elif item[1] == 'sub':
			new_list.append(['-=', item[2], item[3]])
			continue
		elif item[1] == 'mul':
			new_list.append(['*=', item[2], item[3]])
			continue
		elif item[1] == 'and':
			if item[2] == item[3]:
				new_list.append(['=', 'ZF', '(' + item[2] + ' == 0)'])
				continue
			new_list.append(['&=', item[2], item[3]])
			continue
		elif item[1] == 'xor':
			if item[2] == item[3]:
				new_list.append(['=', item[2], '0'])
				continue
			new_list.append(['^=', item[2], item[3]])
			continue
		new_list.append(item)
	return new_list

def get_block_type(block):
	code = block['code']
	if code[-1][0] == 'ret':
		return 'ret'
	if code[-1][0] == 'jmp':
		return 'jmp'
	if code[-1][0] == 'jcc':
		return 'jcc'
	return 'join'

def get_blocks_in_out(blocks):
	come_from = {}
	go_to = {}
	for iblock in range(0, len(blocks)):
		block = blocks[iblock];
		type = get_block_type(block)
		code = block['code']
		block['iblock'] = iblock
		block['type'] = type
		if type == 'jmp':
			label = code[-1][2]
			come_from[label_to_iblock[label]] = iblock
			go_to[iblock] = label_to_iblock[label]
		elif type == 'jcc':
			label = code[-1][2]
			come_from[label_to_iblock[label]] = iblock
			come_from[iblock + 1] = iblock
			go_to[iblock] = label_to_iblock[label]
		elif type == 'join':
			come_from[iblock + 1] = iblock
			go_to[iblock] = iblock + 1
		elif type == 'ret':
			go_to[iblock] = -1
		if block['label'] == function:
			come_from[iblock] = -1
		block['go_to'] = go_to
	for iblock in range(0, len(blocks)):
		block = blocks[iblock]
		block['come_from'] = []
		block['go_to'] = []
	for iblock in range(0, len(blocks)):
		block = blocks[iblock]
		for key, value in come_from.items():
			if value == iblock:
				if not(key in block['go_to']):
					block['go_to'].append(key)
			if key == iblock:
				if not(value in block['come_from']):
					block['come_from'].append(value)
		for key, value in go_to.items():
			if key == iblock:
				if not(value in block['go_to']):
					block['go_to'].append(value)
			if value == iblock:
				if not(key in block['come_from']):
					block['come_from'].append(key)
	return come_from, go_to, blocks

def stage1(code):
	code = optimize_code(code)
	global label_map1, label_map2, label_to_iblock, iblock_to_label
	label_map1, label_map2, code = simplify_labels(code)
	label_to_iblock, iblock_to_label, blocks = split_to_blocks(code)
	come_from, go_to, blocks = get_blocks_in_out(blocks)
	print('--- label_map1 ---')
	print(label_map1)
	print('--- label_map2 ---')
	print(label_map2)
	print('--- iblock_to_label ---')
	print(iblock_to_label)
	print('--- label_to_iblock ---')
	print(label_to_iblock)
	print('--- come_from ---')
	print(come_from)
	print('--- go_to ---')
	print(go_to)
	return blocks

def stage2(blocks):
	return blocks

def stage3(blocks):
	return blocks

def item_to_text(item):
	if item[0] == 'label':
		return item[1] + ':'
	elif item[0] == '=':
		return item[1] + ' = ' + item[2] + ';'
	elif item[0] == 'jmp':
		return 'goto ' + item[2] + ';'
	elif item[0] == 'stack':
		if item[1] == 'push':
			return 'push ' + item[2] + ';'
		elif item[1] == 'pop':
			return 'pop ' + item[2] + ';'
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

def print_blocks(blocks):
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
	for iblock in range(0, len(blocks)):
		block = blocks[iblock]
		text += "\n"
		text += "// Block #" + str(iblock) + \
		        ' (type:' + block['type'] + \
		        ", come_from:" + str(block['come_from']) + \
		        ", go_to:" + str(block['go_to']) + \
		        ", label:" + str(block['label']) + \
		        ")\n"
		for item in block['code']:
			text += str(item_to_text(item)) + "\n"
	if function != None:
		text += "\n}\n"
	print(text)

def unittest():
	data = text_to_code('A = 1')
	assert data_to_text(data) == 'A = 1;'
	data = text_to_code('push eax')
	assert data_to_text(data) == 'push eax;'
	data = text_to_code('pop eax')
	assert data_to_text(data) == 'pop eax;'
	data = text_to_code('push eax\npop ebx')
	assert data_to_text(data) == 'push eax;\npop ebx;'
	replace_dict = {}
	assert code_match(replace_dict, text_to_code('push eax'), text_to_code('push REG0'))
	assert replace_dict['REG0'] == 'eax'
	replace_dict = {}
	assert not(code_match(replace_dict, text_to_code('push eax'), text_to_code('push ebx')))
	print("unittest() ok")

def main(argc, argv):
	unittest()
	print('--- spec ---')
	load_spec("user32.spec", "user32")
	load_spec("kernel32.spec", "kernel32")
	load_spec("win32k.spec", "win32k")
	load_spec("imm32.spec", "IMM32")
	load_spec("ntdll.spec", "ntdll")
	#print(spec)
	#print('---')
	code = file_to_code(argv[1])
	blocks = stage1(code)
	blocks = stage2(blocks)
	blocks = stage3(blocks)
	print('--- blocks ---')
	print(blocks)
	print('--- print_blocks ---')
	print_blocks(blocks)

import sys
main(len(sys.argv), sys.argv)
