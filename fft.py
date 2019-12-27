import numpy as np
from spectrum import *
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
(f, plots) = plt.subplots(3)
seconds = [float(n) * window for n in range(0,len(timeDomain))]
plots[0].plot(seconds,timeDomain)
plots[0].set_title("Packets over time")
plots[0].set(xlabel="Seconds")


freqDomain = np.fft.fft(np.array(timeDomain))
samplingFrequency = 1.0/float(window)
n=len(freqDomain)
frequencies = np.fft.fftfreq(n, 1/window)
frequencyIndices = frequencies


fwindow = np.hanning(len(timeDomain))
fd = np.fft.fft(np.array(timeDomain) * fwindow)
plots[1].plot(frequencyIndices,fd)
plots[1].set_title("Frequencies")
plots[1].set(xlabel="Frequency")

p = speriodogram(np.array(timeDomain), len(timeDomain), sampling=window)
plots[2].plot(p)
plots[2].set(xlabel="Power")
#plots[1].plot(frequencyIndices,freqDomain)
#plots[1].set_title("Frequencies")
#plots[1].set(xlabel="Frequency")

plt.show()
