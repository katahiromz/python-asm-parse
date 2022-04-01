#!/usr/bin/env python3

spec = {}

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

# Unknown register: X0, X1, X2, ...
def is_unknown_reg(text):
	if text[0] != 'X':
		return false
	return is_dec(text[1:])

def load_spec(file, module_name):
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
					spec[func_name] = {'function': func_name, 'module': module_name, 'num_params': num_params}
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
			spec[func_name] = {'function': func_name, 'module': module_name, 'num_params': len(params), 'params': params}

def parse_disasm(addr, hex, ope, operands):
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
	if ope == 'call':
		label = operands[0].split(' ')[0]
		return ['call', label]
	elif ope == 'jmp':
		label = operands[0].split(' ')[0]
		return ['jmp', label]
	elif ope[0] == 'j':
		label = operands[0].split(' ')[0]
		return ['jcc', ope, label]
	elif ope == 'ret':
		if len(operands) >= 1:
			return ['ret', operands[0]]
		else:
			return ['ret']
	else:
		type = 'insn'
		if ope == 'push' or ope == 'pop':
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

def parse_text(text):
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
		addr = ''
		hex = ''
		if is_hex(field0) and is_hex(field1):
			addr = field0
			hex = field1
			items = items[2:]
		operands = ' '.join(items[1:]).split(',')
		ope = items[0]
		ary = parse_disasm(addr, hex, ope, operands)
		if (len(ary) > 0):
			data.append(ary)
			continue
		print('Invalid line: ' + line)
	return data

def load_and_parse(file):
	data = []
	with open(file, 'r') as fin:
		text = fin.read()
		data = parse_text(text)
	return data

def stage1(data):
	return data
def stage2(data):
	return data
def stage3(data):
	return data
def print_data(data):
	for item in data:
		print(item)

def main(argv):
	load_spec("user32.spec", "user32")
	load_spec("imm32.spec", "IMM32")
	load_spec("win32k.spec", "win32k")
	#print(spec)
	data = load_and_parse(argv[1])
	data = stage1(data)
	data = stage2(data)
	data = stage3(data)
	print('---')
	print_data(data)

import sys
main(sys.argv)
