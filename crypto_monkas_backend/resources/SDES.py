from ctypes.wintypes import SHORT
from io import BytesIO
from multiprocessing.sharedctypes import Value
from flask_restful import Resource, abort
import numpy as np
from sys import path, version_info
import base64

path.append("../common")

from common import utils

IP = [2, 6, 3, 1, 4, 8, 5, 7]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

S0 = [  ['01', '00', '11', '10'],
        ['11', '10', '01', '00'],
        ['00', '10', '01', '11'],
        ['11', '01', '11', '10']]

S1 = [  ['00', '01', '10', '11'],
        ['10', '00', '01', '11'],
        ['11', '00', '01', '00'],
        ['10', '01', '00', '11']]
shortcut = {'00':0, '01':1, '10':2, '11':3}

def str_to_bin(string : str):
    output = ''
    for chr in string:
        a = bin(ord(chr))[2:]
        a = '0' * (8 - len(a)) + a
        output += a
    return output

def bin_to_str(binstr : str):
    output = ''
    i = 0
    while i < len(binstr):
        output += chr(int(binstr[i:i+8], 2))
        i+= 8
    return output

def permutate(input, permutation):
    output = ''
    for position in permutation:
        output += input[position - 1] # positions from 1 to n
    return output

def half(input):
    n = len(input) // 2
    left = input[:n]
    right = input[n:]
    return (left, right)

def leftShift(input, n=1):
    return input[n:] + input[:n]

def xor(bits1, bits2):
    return ''.join(map(lambda x, y: str(int(x) ^ int(y)), bits1, bits2))

def lookup(fst, snd):
    return S0[shortcut[fst[:2]]][shortcut[fst[2:]]] + S1[shortcut[snd[:2]]][shortcut[snd[2:]]]

def itinerary(key : str):
    temp = permutate(key, P10)
    left, right = half(temp)
    left, right = leftShift(left), leftShift(right)
    K1 = permutate(left + right, P8)
    left, right = leftShift(left, 2), leftShift(right, 2)
    K2 = permutate(left + right, P8)
    return (K1, K2)

def F(inp : str, key : str):
    temp = permutate(inp, EP)
    temp = xor(temp, key)
    lft, rgt = half(temp)
    lft = lft[0] + lft[3] + lft[1] + lft[2]
    rgt = rgt[0] + rgt[3] + rgt[1] + rgt[2]
    temp = lookup(lft, rgt)
    return permutate(temp, P4)

def enc(entry : str, key: str) -> str:
    binsequence = str_to_bin(entry)
    output = ''
    i = 0
    K1, K2 = itinerary(key)
    while i < len(binsequence):
        block = binsequence[i:i+8]
        block = permutate(block, IP)
        lft, rgt = half(block)
        lft = xor(lft, F(rgt, K1))
        # swaping:
        t = lft
        lft = rgt
        rgt = t
        # end of swaping
        lft = xor(lft, F(rgt, K2))
        block = permutate(lft + rgt, IP_INV)
        output += block
        i += 8
    return output

def dec(entry : str, key: str) -> str:
    binsequence = str_to_bin(entry)
    output = ''
    i = 0
    K1, K2 = itinerary(key)
    while i < len(binsequence):
        block = binsequence[i:i+8]
        block = permutate(block, IP)
        lft, rgt = half(block)
        lft = xor(lft, F(rgt, K2))
        # swaping:
        t = lft
        lft = rgt
        rgt = t
        # end of swaping
        lft = xor(lft, F(rgt, K1))
        block = permutate(lft + rgt, IP_INV)
        output += block
        i += 8
    return output

def sdes_key(key : str):
    key = ''.join(filter(lambda x: x in ('0', '1'), key))
    if len(key) != 10:
        raise ValueError("Key must be of length 10!")
    return key

sdes_enc_parser = utils.sdes_parser(sdes_key)

sdes_dec_parser = utils.sdes_parser(sdes_key)

class SDESEnc(Resource):
    def post(self):
        args = sdes_enc_parser.parse_args()
        entry = args['text']
        key = args['key']
        temp = bin_to_str(enc(entry, key))
        temp = temp.encode('utf-8')
        temp = base64.b64encode(temp)
        output = temp.decode('utf-8')
        return {"output": output}


class SDESDec(Resource):
    def post(self):
        args = sdes_dec_parser.parse_args()
        entry = args['text']
        key = args['key']
        temp = entry.encode('utf-8')
        temp = base64.b64decode(temp)
        temp = temp.decode('utf-8')
        output = bin_to_str(dec(temp, key))
        return {"output": output}
