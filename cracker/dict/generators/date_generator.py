#!/usr/bin/python3

import sys

if len(sys.argv) < 3:
	print("Use with %s <start_year> <stop_year> [separator] [special]" % sys.argv[0], file=sys.stderr)
	sys.exit()

if not sys.argv[1].isdigit() or not sys.argv[2].isdigit():
	print("ERROR! Arguments must be numbers! Use with %s <start_year> <stop_year> [separator] [special]" % sys.argv[0], file=sys.stderr)
	sys.exit()

start = int(sys.argv[1])
stop = int(sys.argv[2])
separator = ""


if start < 0 or start >10000 or stop < 0 or stop > 10000:
	print("Arguments must be 0-9999 unless you change this script!", file=sys.stderr)
	sys.exit()

values = set()

if len(sys.argv) >= 4:
	separators = list(sys.argv[3])
	gen_special = False
	if len(sys.argv) == 5:
		gen_special = True

	for separator in separators:
		for month in range(13):
			for day in range(32):
				for year in range(start, stop):
					values.add('%02d%s%02d%s%04d' % (day, separator, month, separator, year))
					values.add('%02d%s%02d%s%04d' % (month, separator, day, separator, year))
					values.add('%04d%s%02d%s%02d' % (year, separator, month, separator, day))
				if gen_special:
					nstart = 0
					nstop = 100
					if (stop -  start < 100):
						nstart = start % 100
						nstop = stop % 100
					for year in range(nstart, nstop):
						values.add('%02d%s%02d%s%02d' % (day, separator, month, separator, year))
						values.add('%02d%s%02d%s%02d' % (month, separator, day, separator, year))
						values.add('%02d%s%02d%s%02d' % (year, separator, month, separator, day))					
else:
	for year in range(start, stop):
		for month in range(13):
			for day in range(32):
				values.add('%02d%02d%04d' % (day, month, year))
				values.add('%02d%02d%04d' % (month, day, year))
				values.add('%04d%02d%02d' % (year, month, day))

for value in values:
	print(value)
