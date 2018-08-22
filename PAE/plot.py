#!/usr/bin/python
import matplotlib.pyplot as plt
import numpy as numpy
import sys


dictionary = {}
inputData = sys.stdin.readlines()
for line in inputData:
	[count, value] =  line.split()
	dictionary[int(value)] = int(count)

keys = sorted(dictionary.keys())
data = []
for key in keys:
	data.append(dictionary[key])

ax=plt.axes()
ax.plot(keys, data, ".")

min = min(data)
max = max(data)
stddev = numpy.std(data)
mean = numpy.mean(data)

fudge = 2
if(len(sys.argv) > 1):
	fudge = int(sys.argv[1])

i = 0
for key in sorted(dictionary, key=dictionary.get, reverse=True)[:10]:
	ax.annotate(str(key),  xy=(key, dictionary[key]), xycoords='data', xytext=(10,400-(i*20)), textcoords='figure pixels',  arrowprops=dict(color="red",  width=0.01, headwidth=4))
	i = i + 1
plt.show()		
