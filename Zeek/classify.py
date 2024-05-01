#!/usr/bin/env python3
import sys
import os
import broker
import numpy as np
import tensorflow as tf
from tensorflow.keras import models, layers
    
def normalize_string(string, length=16):
    if len(string) >= length:
        return string[:length]
    return string.ljust(length, "0")

def ascii_to_bytes(string):
    # Define a list to hold the bytes
    byte_list = []
    # Traverse the string by twos
    for i in range(0, len(string), 2):
        # Convert the two character hex value to an integer, translating from Base 16
        i_val = int(string[i:i+2], 16)
        # Convert the resulting integer into a 1 byte value using the `chr()` function
        byte_val = chr(i_val)
        # Append that byte to the list of bytes
        byte_list.append(byte_val)
    return byte_list

def bytes_to_bits(byte_list):
    bit_list = []
    # Iterate over all of the bytes in the list
    for byte in byte_list:
        # For each byte, we need to test each bit to see if it's on or off
        # We can do this using bit shifting.  We'll start with the  high order
        # bit and work our way down, so we shift from 7 first, 0 last.
        for shift in [7, 6, 5, 4, 3, 2, 1, 0]:
            # Define the mask to isolate a bit by shifting a 1 left
            mask = 1 << shift
            # Apply the mask to isolate the bit in place
            the_shifted_bit = ord(byte) & mask
            # Shift the bit down to the bottom and capture it
            the_bit = the_shifted_bit >> shift
            # Add the bit to our growing list of bits
            bit_list.append(the_bit)
    return np.array(bit_list)

def content_to_features(content_string):
    #bits = bytes_to_bits(ascii_to_bytes(normalize_string(content_string)))
    bites = (np.array([ord(i) for i in ascii_to_bytes(normalize_string(content_string))])-127)/127
    #return np.concatenate((bits,bites))
    return bites

class AnomalyFinder():
    def __init__(self):
        self.classifiers = {}
        files = os.listdir()
        autoencoders = [ i  for i in files if i[:11]=='autoencoder']
        for encoder in autoencoders:
            model = tf.keras.models.load_model(encoder)
            _, protocol, threshold = encoder.split('_')
            threshold = float(threshold[:-6]) # Account for the .keras postfix
            self.classifiers[protocol] = (model, threshold)
            print(f'Loaded {protocol} model')


    def has_classifier(self, protocol):
        return protocol in self.classifiers.keys()
        
    def add_classifier(self, protocol, data):
        # Split the data
        print("This code is part of SEC595. Sorry!")
        
    def evaluate(self, x):
        possibles = {}
        for protocol in self.classifiers:
            (model, threshold) = self.classifiers[protocol]
            loss = tf.keras.losses.mae(x, model.predict(np.array([x]), verbose=False))
            if(loss <= threshold):
                closeness = 1 - float(loss / threshold)
                possibles[protocol] = closeness * 100
        if len(possibles.keys()) < 1:
            answers = ["--> Unknown Protocol! <--"]
        else:
            answers = sorted(possibles.items(), key=lambda item: item[1], reverse=True)
        return len(possibles.keys())>0, answers[:2]

analyzer = AnomalyFinder()
# Setup endpoint and connect to Zeek.
ep = broker.Endpoint()
sub = ep.make_subscriber("sec503/content")
ss = ep.make_status_subscriber(True);
ep.peer("127.0.0.1", 9999)

# Wait until connection is established.
st = ss.get()

if not (type(st) == broker.Status and st.code() == broker.SC.EndpointDiscovered):
    print("could not connect")
    sys.exit(0)

DEBUG = 1 if len(sys.argv) > 1 else 0
print("Connected!  Waiting for stream content.")
while 1:
    (t, d) = sub.get()
    (orig_h, orig_p, resp_h, resp_p, content) = broker.zeek.Event(d).args()
    known, category = analyzer.evaluate(np.array(contentToFeatures(content)))
    if(not known):
        print(f'{orig_h}:{orig_p} -> {resp_h}:{resp_p} : Unknown Application Protocol')
    if(DEBUG):
        print(f'{orig_h}:{orig_p} -> {resp_h}:{resp_p} : {category}')

