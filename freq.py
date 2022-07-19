import numpy as np
import matplotlib.pyplot as plt
import sys
import argparse

parser = argparse.ArgumentParser(description="Generate time domain and frequency domain plots of the input data.")
parser.add_argument('-w','--window', default=60.0, type=float, dest="window", help="Define the time window for the time domain histogram and frequency analysis.")
parser.add_argument('-f', '--file', default=None, type=str, dest="output_filename", help="Output the graph to a file rather than to the screen.")
window = parser.parse_args().window
output_filename = parser.parse_args().output_filename
bin=0
startingTime = 0.0
endingTime = 0.0
binLimit=-1.0
samples = 0
timeDomain = []
for line in sys.stdin:
    (timestamp, host)=line.split(" ")
    ts = float(timestamp)
    if(binLimit == -1.0):
       startingTime = ts
       binLimit = ts + window
       samples = 1
       timeDomain.append(0)
    while(ts > binLimit):
        timeDomain.append(0)
        samples += 1
        bin += 1
        binLimit += window
    if(ts <= binLimit):
        timeDomain[bin] += 1
        samples += 1
    endingTime = ts

if bin % 2 == 1:
    bin+=1
    timeDomain.append(0)

seconds = [float(n) * window for n in range(0,len(timeDomain))]
plt.plot(seconds,timeDomain)
plt.title("Packets over time")
plt.xlabel("Seconds")
if(output_filename):
	plt.savefig(output_filename, dpi=150, format='png')
else:
	plt.show()

