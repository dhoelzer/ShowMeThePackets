import numpy as np
import matplotlib.pyplot as plt
import sys
import argparse

parser = argparse.ArgumentParser(description="Generate time domain and frequency domain plots of the input data.")
parser.add_argument('-w','--window', default=60.0, type=float, dest="window", help="Define the time window for the time domain histogram and frequency analysis.")
window = parser.parse_args().window
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
plt.show()

