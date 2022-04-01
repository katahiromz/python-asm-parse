#!/usr/bin/env python3

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
			print('Invalid line: ' + line)
			continue
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

def main(argv):
	data = load_and_parse(argv[1])
	print('---')
	for item in data:
		print(item)

import sys
main(sys.argv)
