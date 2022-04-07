#!/usr/bin/env python3

import re

spec = {}
function = None
num_params = -1
label_to_iblock = {}
iblock_to_label = {}
label_map1 = {}
label_map2 = {}
istart = 0
edges = []

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
	if text[:3] == 'MEM' and is_dec(text[3:]):
		return True
	size = get_mem_size(text)
	if size <= 0:
		return False
	addr = get_mem_addr(text)
	return is_unknown(addr)

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
	if text[0] == '[':
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

def operand_match(op0, op1, replace_dict):
	if op0 == op1:
		return True
	if not(is_unknown(op0)) and is_unknown(op1):
		if is_reg(op0, True) and is_reg(op1, True):
			replace_dict[op1] = op0
			return True
		if is_mem(op0, True) and is_mem(op1, True):
			size0 = get_mem_size(op0)
			size1 = get_mem_size(op1)
			if size0 > 0 and size1 > 0:
				addr0 = get_mem_addr(op0)
				addr1 = get_mem_addr(op1)
				replace_dict[addr1] = addr0
				return True
			replace_dict[op1] = op0
			return True
		replace_dict[op1] = op0
		return True
	return False

def asm_match(asm0, asm1, replace_dict):
	type0 = asm0[0]
	type1 = asm1[0]
	if type0 != type1:
		return False
	operands0 = asm0[1:]
	operands1 = asm1[1:]
	if len(operands0) != len(operands1):
		return False
	for i in range(len(operands0)):
		op0 = operands0[i]
		op1 = operands1[i]
		if not(operand_match(op0, op1, replace_dict)):
			return False
	return True

def asm_replace(asm, key, value, use_re = True):
	import copy
	asm = copy.deepcopy(asm)
	for k in range(len(asm)):
		if key.find('[') == -1 and key.find('(') == -1:
			import re
			asm[k] = re.sub(r'\b' + key + r'\b', value, asm[k])
		else:
			asm[k] = asm[k].replace(key, value)
	return asm

def code_replace(code, replace_dict):
	import copy
	code = copy.deepcopy(code)
	for i in range(len(code)):
		for key, value in replace_dict.items():
			code[i] = asm_replace(code[i], key, value)
	return code

def code_match_ex(code0, code1, replace_dict):
	if len(code0) != len(code1):
		return False
	retry = True
	while retry:
		retry = False
		for i in range(len(code0)):
			dict0 = {}
			if not(asm_match(code0[i], code1[i], dict0)):
				return False
			if len(dict0) > 0:
				code0 = code_replace(code0, dict0)
				code1 = code_replace(code1, dict0)
				replace_dict.update(dict0)
				retry = True
				break
	return True

def code_match(code0, code1):
	replace_dict = {}
	return code_match_ex(code0, code1, replace_dict)

def code_check_assertion(code):
	for i in range(len(code)):
		asm = code[i]
		if asm[0] == 'assert':
			if is_unknown(asm[2]) or is_unknown(asm[4]):
				continue
			if asm[3] == '===':
				if asm[2] != asm[4]:
					return False
			elif asm[3] == '!==':
				if asm[2] == asm[4]:
					return False
	return True

def code_substitute(code, text0, text1, assert_text = ''):
	import copy
	code = copy.deepcopy(code)
	code0 = text_to_code(text0)
	code1 = text_to_code(text1)
	assertion = text_to_code(assert_text)
	retry = True
	while retry:
		retry = False
		for i in range(len(code) - len(code0) + 1):
			subcode = code[i : i + len(code0)]
			dict0 = {}
			if code_match_ex(subcode, code0, dict0):
				if code_check_assertion(code_replace(assertion, dict0)):
					code[i : i + len(code0)] = code_replace(code1, dict0)
					retry = True
					break
	return code

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
			line = re.sub(r'\bstdcall\b', '', line)
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
	for i in range(len(operands)):
		operands[i] = operands[i].strip()
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
		return ['=', 'mov', operands[0], operands[1]]
	elif ope == 'if-goto':
		ary = ['if-goto']
		ary.extend(operands)
		return ary
	else:
		type = ''
		if ope == 'call':
			type = 'call'
			if operands[0][:11] == 'dword ptr [':
				operands = [get_mem_addr(operands[0])]
			else:
				operands = [operands[0].split(' ')[0]]
		if ope == 'sub':
			type = 'call'
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
		elif ope == 'assert':
			type = 'assert'
		else:
			type = 'insn'
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
		import re
		result = re.match(r'([A-Za-z][A-Za-z0-9_]+?)\((.*)\)', line)
		if result:
			ope = 'sub'
			name = result.group(1)
			params = result.group(2).split(',')
			operands = [name]
			operands.extend(params)
		elif ieq != -1:
			s0 = line[:ieq].strip()
			s1 = line[ieq + 3:].strip()
			ope = '='
			operands = [s0, s1]
		elif line.find('if') == 0 and line.find('goto') != -1:
			ope = 'if-goto'
			import re
			result = re.match(r'if ?\(!\((.*?) (.*?) (.*?)\)\) goto ([^ \r\n;]+)', line)
			if result:
				operands = [result.group(1), result.group(2), result.group(3), result.group(4), '!']
			else:
				result = re.match(r'if ?\((.*?) (.*?) (.*?)\) goto ([^ \r\n;]+)', line)
				if result:
					operands = [result.group(1), result.group(2), result.group(3), result.group(4)]
				else:
					print('ERROR: invalid line: ' + line)
					continue
		elif line.find('assert') == 0:
			ope = 'assert'
			result = re.match(r'assert (.*) (===|!==) (.*)', line)
			if result:
				operands = [result.group(1), result.group(2), result.group(3)]
			else:
				print('ERROR: invalid line: ' + line)
				continue
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
			if ope == 'rep':
				operands = [items[1]]
				operands.extend(' '.join(items[2:]).split(','))
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
	function = None
	for item in code:
		if item[0] == 'label':
			i0 = item[1].find('+')
			if i0 == -1 and function is None:
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
		if item[0] == 'label' and item[1] in label_map1:
			item[1] = label_map1[item[1]]
		elif item[0] == 'jmp' and item[2] in label_map1:
			item[2] = label_map1[item[2]]
		elif item[0] == 'jcc' and item[2] in label_map1:
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
	edges = []
	for iblock in range(len(blocks)):
		block = blocks[iblock];
		type = get_block_type(block)
		code = block['code']
		block['iblock'] = iblock
		block['type'] = type
		if type == 'jmp':
			label = code[-1][2]
			edges.append([iblock, label_to_iblock[label]])
		elif type == 'jcc':
			label = code[-1][2]
			edges.append([iblock, iblock + 1])
			edges.append([iblock, label_to_iblock[label]])
		elif type == 'join':
			edges.append([iblock, iblock + 1])
		if 'label' in block and block['label'] == function:
			global istart
			istart = iblock
	for iblock in range(len(blocks)):
		block = blocks[iblock]
		block['pred'] = []
		block['succ'] = []
	for iblock in range(len(blocks)):
		block = blocks[iblock]
		for pair in edges:
			if pair[0] == iblock:
				block['succ'].append(pair[1])
			if pair[1] == iblock:
				block['pred'].append(pair[0])
	return edges, blocks

def asm_int(text):
	if text[-1] == 'h':
		return int(text[0:-1], 16)
	else:
		return int(text)

def code_check_num_params(code):
	for i in range(len(code)):
		asm = code[i]
		if asm[0] == 'ret' and len(asm) == 3 and asm[2] != '':
			return int(asm_int(asm[2]) / 4)
	return -1

def get_block_by_iblock(blocks, iblock):
	for i in range(len(blocks)):
		if blocks[i]['iblock'] == iblock:
			return blocks[i]
	return None

# tree = [inode, subtrees]
def tree_contains_node(tree, node):
	if tree[0] == node:
		return True
	subtrees = tree[1]
	for subtree in subtrees:
		if tree_contains_node(subtree, node):
			return True
	return False

def get_tree_by_inode(tree, inode):
	if tree[0] == node:
		return tree
	subtrees = tree[1]
	for subtree in subtrees:
		node = get_tree_by_inode(subtree, inode)
		if node:
			return node
	return None

def block_from_iblock(blocks, iblock):
	for block in blocks:
		if block['iblock'] == iblock:
			return block
	return None

def dominators(blocks, inode):
	global istart
	ret = [inode]
	if istart == inode:
		return ret
	block = block_from_iblock(blocks, inode)
	pred = block['pred']
	dom = None
	for p in pred:
		dom0 = dominators(blocks, p)
		if dom is None:
			dom = dom0
		else:
			dom = list(set(dom) & set(dom0))
	if dom is None:
		return ret
	return list(set(ret) | set(dom))

def get_ifgoto_condition(asm):
	if len(asm) == 5:
		return asm[1] + ' ' + asm[2] + ' ' + asm[3]
	if len(asm) == 6 and asm[5] == '!':
		return '!(' + asm[1] + ' ' + asm[2] + ' ' + asm[3] + ')'

def get_not_condition(cond):
	cond = cond.strip()
	if cond == 'TRUE' or cond == '':
		return 'FALSE'
	if cond == 'FALSE':
		return 'TRUE'
	import re
	result = re.match(r'!\((.*?) (.*?) (.*?)\)', cond)
	if result:
		return result.group(1) + ' ' + result.group(2) + '  ' + result.group(3)
	result = re.match(r'(.*?) (.*?) (.*?)', cond)
	if result:
		left = result.group(1)
		ope = result.group(2)
		right = result.group(3)
		if ope == '==':
			ope = '!='
		elif ope == '!=':
			ope = '=='
		elif ope == '<':
			ope = '>='
		elif ope == '>':
			ope = '<='
		elif ope == '<=':
			ope = '>'
		elif ope == '>=':
			ope = '<'
		elif ope == '&':
			return '!(' + left + ' ' + ope + ' ' + right + ')'
		else:
			raise
		return left + ' ' + ope + ' ' + right
	raise

def is_control_flow_ok(blocks):
	for block in blocks:
		code = block['code']
		type = block['type']
		block['condition'] = ''
		if type == 'jcc':
			if code[-1][0] != 'if-goto':
				return False
			block['condition'] = get_ifgoto_condition(code[-1])
		if type == 'jmp':
			if code[-1][0] != 'jmp':
				return False
	return True

def stage1(code):
	global num_params
	num_params = code_check_num_params(code)
	global label_map1, label_map2, label_to_iblock, iblock_to_label
	label_map1, label_map2, code = simplify_labels(code)
	label_to_iblock, iblock_to_label, blocks = split_to_blocks(code)
	global edges
	edges, blocks = get_blocks_in_out(blocks)
	for iblock in range(len(blocks)):
		block = blocks[iblock]
		code = block['code']
		assert iblock == block['iblock']
		if True:
			code = code_substitute(code, 'push ebp\nmov ebp,esp\nsub esp,X0', 'enter X0')
			code = code_substitute(code, 'push ebp\nmov ebp,esp', 'enter 0')
			code = code_substitute(code, 'nop', '')
			code = code_substitute(code, 'mov X0,X0', '')
			code = code_substitute(code, 'mov X0,X1', 'X0 = X1')
			code = code_substitute(code, 'xor X0,X0', 'X0 = 0')
			code = code_substitute(code, 'lea X0,[X1]', 'X0 = X1')
			code = code_substitute(code, 'X0 = 0\ninc X0', 'X0 = 1')
			code = code_substitute(code, 'neg X0\nsbb X0,X0\nneg X0', 'X0 = !!X0')
			code = code_substitute(code, 'neg X0\nsbb X0,X0', 'X0 = X0 ? -1 : 0')
			retry = True
			while retry:
				import copy
				old_code = copy.deepcopy(code)
				code = code_substitute(code, 'cmp X0,X1\nX3 = X4', 'X3 = X4\ncmp X0,X1', 'assert X3 !== X0\nassert X3 !== X1')
				code = code_substitute(code, 'cmp X0,X1\npush X2', 'push X2\ncmp X0,X1', 'assert X2 !== esp')
				code = code_substitute(code, 'test X0,X1\nX3 = X4', 'X3 = X4\ntest X0,X1', 'assert X3 !== X0\nassert X3 !== X1')
				code = code_substitute(code, 'test X0,X1\npush X2', 'push X2\ntest X0,X1', 'assert X2 !== esp')
				code = code_substitute(code, 'push X0\npop X1', 'X1 = X0')
				retry = not(code_match(old_code, code))
			code = code_substitute(code, 'dec X0\nje X1', 'X0 = X0 - 1\nif (X0 == 0) goto X1')
			code = code_substitute(code, 'dec X0\njne X1', 'X0 = X0 - 1\nif (X0 != 0) goto X1')
			code = code_substitute(code, 'dec X0\nja X1', 'X0 = X0 - 1\nif (X0 > 0) goto X1')
			code = code_substitute(code, 'dec X0\njb X1', 'X0 = X0 - 1\nif (X0 < 0) goto X1')
			code = code_substitute(code, 'inc X0\nje X1', 'X0 = X0 + 1\nif (X0 == 0) goto X1')
			code = code_substitute(code, 'inc X0\njne X1', 'X0 = X0 + 1\nif (X0 != 0) goto X1')
			code = code_substitute(code, 'inc X0\nja X1', 'X0 = X0 + 1\nif (X0 > 0) goto X1')
			code = code_substitute(code, 'inc X0\njb X1', 'X0 = X0 + 1\nif (X0 < 0) goto X1')
			code = code_substitute(code, 'sub X0,X1\nje X2', 'X0 = X0 - X1\nif (X0 == 0) goto X2')
			code = code_substitute(code, 'sub X0,X1\njne X2', 'X0 = X0 - X1\nif (X0 != 0) goto X2')
			code = code_substitute(code, 'sub X0,X1\nja X2', 'X0 = X0 - X1\nif (X0 > 0) goto X2')
			code = code_substitute(code, 'sub X0,X1\njb X2', 'X0 = X0 - X1\nif (X0 < 0) goto X2')
			code = code_substitute(code, 'add X0,X0', 'X0 = 2 * X0')
			code = code_substitute(code, 'and X0,0', 'X0 = 0')
			code = code_substitute(code, 'and X0,X1', 'X0 = X0 & X1')
			code = code_substitute(code, 'or X0,0FFFFFFFFh', 'X0 = -1')
			code = code_substitute(code, 'or X0,X1', 'X0 = X0 | X1')
			code = code_substitute(code, 'not X0', 'X0 = ~X0')
			code = code_substitute(code, 'push X0\nX1 = X2', 'X1 = X2\npush X0', 'assert X0 !== X1')
			code = code_substitute(code, 'test X0,X0\nje X1', 'if (X0 == 0) goto X1')
			code = code_substitute(code, 'test X0,X0\njne X1', 'if (X0 != 0) goto X1')
			code = code_substitute(code, 'test X0,X0\nja X2', 'if (X0 > 0) goto X2')
			code = code_substitute(code, 'test X0,X0\njae X2', 'if (X0 >= 0) goto X2')
			code = code_substitute(code, 'test X0,X0\njb X2', 'if (X0 < 0) goto X2')
			code = code_substitute(code, 'test X0,X0\njbe X2', 'if (X0 <= 0) goto X2')
			code = code_substitute(code, 'test X0,X1\njne X2', 'if (X0 & X1) goto X2')
			code = code_substitute(code, 'test X0,X1\nje X2', 'if (!(X0 & X1)) goto X2')
			code = code_substitute(code, 'cmp X0,X1\nje X2', 'if (X0 == X1) goto X2')
			code = code_substitute(code, 'cmp X0,X1\njne X2', 'if (X0 != X1) goto X2')
			code = code_substitute(code, 'cmp X0,X1\nja X2', 'if (X0 > X1) goto X2')
			code = code_substitute(code, 'cmp X0,X1\njae X2', 'if (X0 >= X1) goto X2')
			code = code_substitute(code, 'cmp X0,X1\njb X2', 'if (X0 < X1) goto X2')
			code = code_substitute(code, 'cmp X0,X1\njbe X2', 'if (X0 <= X1) goto X2')
			code = code_substitute(code, 'X0 = X1\npush X0\npush X0\npush X0', 'X0 = X1\npush X1\npush X1\npush X1')
			code = code_substitute(code, 'X0 = X1\npush X0\npush X0', 'X0 = X1\npush X1\npush X1')
			code = code_substitute(code, 'X0 = X1\npush X0', 'X0 = X1\npush X1')
			code = code_substitute(code, 'add X0,X1', 'X0 = X0 + X1')
			code = code_substitute(code, 'sub X0,X1', 'X0 = X0 - X1')
			code = code_substitute(code, 'inc X0', 'X0 = X0 + 1')
			code = code_substitute(code, 'dec X0', 'X0 = X0 - 1')
			code = code_substitute(code, 'shl X0,X1', 'X0 = X0 << X1')
			code = code_substitute(code, 'shr X0,X1', 'X0 = X0 >> X1')
			code = code_substitute(code, 'push X0\nX1 = X2', 'X1 = X2\npush X0', 'assert X0 !== X1')
			code = code_substitute(code, 'push X0\npop X1', 'X1 = X0')
			code = code_substitute(code, 'rep movs dword ptr es:[edi],dword ptr [esi]', 'memcpy(edi,esi,ecx)')
			code = code_substitute(code, 'X0 = X1\nX2 = X0', 'X0 = X1\nX2 = X1')
			code = code_substitute(code, 'X0 = X1\nX2 = dword ptr [X0]', 'X0 = X1\nX2 = dword ptr [X1]')
			code = code_replace(code, {'dword ptr [ebp+8]': 'ARGV[1]'})
			code = code_replace(code, {'dword ptr [ebp+0Ch]': 'ARGV[2]'})
			code = code_replace(code, {'dword ptr [ebp+10h]': 'ARGV[3]'})
			code = code_replace(code, {'dword ptr [ebp+14h]': 'ARGV[4]'})
			code = code_replace(code, {'dword ptr [ebp+18h]': 'ARGV[5]'})
			code = code_replace(code, {'dword ptr [ebp+1Ch]': 'ARGV[6]'})
			code = code_replace(code, {'dword ptr [ebp+20h]': 'ARGV[7]'})
			code = code_replace(code, {'dword ptr [ebp+24h]': 'ARGV[8]'})
			code = code_replace(code, {'dword ptr [ebp+28h]': 'ARGV[9]'})
			code = code_replace(code, {'0FFFFFFFFh': '-1'})
		block['code'] = code
	print('--- label_map1 ---')
	print(label_map1)
	print('--- label_map2 ---')
	print(label_map2)
	print('--- iblock_to_label ---')
	print(iblock_to_label)
	print('--- label_to_iblock ---')
	print(label_to_iblock)
	return blocks

def blocks_add_flags(blocks):
	for block in blocks:
		block['flag'] = False
	return blocks

def edges_add_flags(edges):
	new_edges = []
	for edge in edges:
		new_edges.append([edge[0], edge[1], False])
	return new_edges

def stage2(blocks):
	global edges
	edges = edges_add_flags(edges)
	blocks = blocks_add_flags(blocks)
	global istart
	if is_control_flow_ok(blocks):
		pass
	return blocks

def stage3(blocks):
	return blocks

def asm_to_text(asm):
	if asm[0] == 'label':
		return asm[1] + ':'
	elif asm[0] == '=':
		return asm[2] + ' = ' + asm[3] + ';'
	elif asm[0] == 'jmp':
		return 'goto ' + asm[2] + ';'
	elif asm[0] == 'stack':
		if asm[1] == 'push':
			return 'push ' + asm[2] + ';'
		elif asm[1] == 'pop':
			return 'pop ' + asm[2] + ';'
		elif asm[1] == 'enter':
			text = 'enter ' + asm[2] + ";\n"
			if asm[2] == '0':
				text += '//EBP := [(ret addr), ARGV[1], ...];'
			else:
				text += '//EBP := [(local variables ' + asm[2] + ' bytes), (ret. addr.), ARGV[1], ...];'
			return text
		else:
			return str(asm)
	elif asm[0] == 'ret':
		return 'return eax or void;'
	elif asm[0] == 'assert':
		return 'assert ' + asm[1] + ' ' + asm[2] + ' ' + asm[3] + ';'
	elif asm[0] == 'if-goto':
		return 'if (' + get_ifgoto_condition(asm) + ') goto ' + asm[4] + ';'
	elif asm[0] == 'call':
		if asm[1] == 'sub':
			return asm[2] + '(' + ', '.join(asm[3:]) + ');'
		if asm[1] == 'function':
			return 'eax = ' + asm[2] + '(' + ', '.join(asm[:2]) + ');'
	return str(asm)

def code_to_text(code):
	text = ''
	for asm in code:
		if text != '':
			text += '\n';
		text += asm_to_text(asm)
	return text;

def print_blocks(blocks):
	text = ''
	global num_params
	if function != None:
		text += 'def ' + function + '('
		if function in spec:
			num_params = int(spec[function]['num_params'])
		params = ''
		if num_params == 0:
			params = 'void'
		elif num_params == -1:
			params = '...'
		else:
			for i in range(num_params):
				if params != '':
					params += ', '
				params += 'ARGV[' + str(i + 1) + ']'
		text += params + ")\n"
		text += "{\n"
	for i in range(len(blocks)):
		block = blocks[i]
		iblock = block['iblock']
		text += "\n"
		if True:
			text += "// Block #" + str(iblock) + \
			        ' (type:' + block['type'] + \
			        ", pred:" + str(block['pred']) + \
			        ", succ:" + str(block['succ']) + \
			        ", dom:" + str(dominators(blocks, iblock)) + \
			        ", cond:(" + str(block['condition']) + ')'
			if 'label' in block:
				text += ", label:" + str(block['label'])
			text += ")\n"
		for asm in block['code']:
			text += str(asm_to_text(asm)) + "\n"
	if function != None:
		text += "\n}\n"
	print(text)

def unittest():
	assert code_to_text(text_to_code('A = 1')) == 'A = 1;'
	assert code_to_text(text_to_code('push eax')) == 'push eax;'
	assert code_to_text(text_to_code('pop eax')) == 'pop eax;'
	assert code_to_text(text_to_code('push eax\npop ebx')) == 'push eax;\npop ebx;'
	assert code_match(text_to_code('push eax'), text_to_code('push REG0'))
	assert not(code_match(text_to_code('push eax'), text_to_code('push ebx')))
	assert code_match(text_to_code('mov eax, ebx'), text_to_code('mov REG0, REG1'))
	assert not(code_match(text_to_code('mov eax, ebx'), text_to_code('mov REG0, REG0')))
	assert code_match([['insn', 'mov', 'eax', 'dword ptr [ebp+0Ch]']], text_to_code('mov REG0, X0'))
	assert code_match([['insn', 'lea', 'eax', '[ebp-14h]']], text_to_code('lea X0, [X1]'))
	assert code_match(text_to_code('test edx,edx\neax = ebx'), text_to_code('test X0,X1\nX3 = X4'))
	assert code_to_text(code_substitute(text_to_code('push 7\npop ecx'), 'push X0\npop X1', 'X1 = X0')) == 'ecx = 7;'
	print("unittest() ok")

def text_code():
	global istart
	istart = 0
	return "\n".join([
		'Function:',
		'call test1',
		'cmp eax, 0',
		'je label4',
		'label0:',
		'call test2',
		'cmp eax, 0',
		'ja label2',
		'label1:',
		'esi = 0',
		'jmp label3',
		'label2:',
		'edi = 123',
		'esi = 456',
		'ecx = 32',
		'memcpy(edi, esi, ecx)',
		'label3:',
		'eax = esi',
		'label4:',
		'ret'
	])

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
	if argc >= 2:
		code = file_to_code(argv[1])
	else:
		code = text_to_code(text_code())
	blocks = stage1(code)
	blocks = stage2(blocks)
	blocks = stage3(blocks)
	print('--- blocks ---')
	for block in blocks:
		print(block['code'])
	print('--- print_blocks ---')
	print_blocks(blocks)

import sys
main(len(sys.argv), sys.argv)
