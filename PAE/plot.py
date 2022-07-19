#!/usr/bin/python
import matplotlib.pyplot as plt
import numpy as numpy
import sys

output_filename = None
if len(sys.argv) > 1:
	output_filename = sys.argv[1]
dictionary = {}
inputData = sys.stdin.readlines()
for line in inputData:
	[count, value] =  line.split()
	dictionary[int(value)] = int(count)

keys = sorted(dictionary.keys())
data = []
for key in keys:
	data.append(dictionary[key])

plt.figure(figsize=(12,6))
plt.scatter(keys, data, s=0.5)
minimum = min(data)
maximum = max(data)
stddev = numpy.std(data)
mean = numpy.mean(data)
plt.plot([0,max(keys)], [mean, mean], '-', c='r')
plt.plot([0,max(keys)], [mean+stddev, mean+stddev], '-', c='y')
plt.plot([0, max(keys)], [mean-stddev, mean-stddev], '-', c='y')
plt.grid()
#fudge = 2
#if(len(sys.argv) > 1):
#	fudge = int(sys.argv[1])

i = 0
for key in sorted(dictionary, key=dictionary.get, reverse=True)[:10]:
	plt.annotate(str(key),  xy=(key, dictionary[key]), xycoords='data', xytext=(10,400-(i*20)), textcoords='figure pixels',  arrowprops=dict(color="red",  width=0.01, headwidth=4))
	i = i + 1
if(output_filename):
	plt.savefig(output_filename, dpi=150, format='png')
else:
	plt.show()		
