
words = set()
ordered_words = []

def process_line(line):
	line = line.strip().lower()	
	while len(line) > 2 and line[-2] == "'":
		line = line[:-2]

	return line

with open("english_dic.txt", "r") as fd:
	for line in fd:
		line = process_line(line)

		if len(line) > 3 and line[0] != "#" and all(ord(char) < 128 for char in line) and line[0] != "'" and line[-1] != "'" and "." not in line:
			if line not in words:
				ordered_words.append(line)
			words.add(line)


for word in ordered_words:
	print word