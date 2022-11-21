from flask_restful import Resource
from sys import path
import os

path.append("../common")

from common import utils
this = os.getcwd() + "/back/resources/tmp/"
with open(this + "graph.txt", 'r') as f:
    data = f.read()
graph = eval(data)

with open(this + "count.txt", 'r') as f:
    data = f.read()
count = eval(data)

def gamma_point(point : str):
    c1, c2 = point.split(", ")
    return (int(c1), int(c2))

def gamma_key(key:str):
    return list(map(int, key.split('-')))


gamma_enc_parser = utils.gamma_parser(gamma_key, gamma_point)

gamma_dec_parser = utils.gamma_parser(gamma_key, gamma_point)

def enc(txt: str, key : list, point : list):
    abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    dics = [list(map(lambda x: (ord(x) + key[i] - 65) % 26, list(abc)[i:] + list(abc)[:i])) for i in range(26)]
    for i in range(26):
        for j in range(26):
            p = (i - point[0], j - point[1])
            if p not in count:
                count[p] = 0
            dics[i][j] = chr(((dics[i][j] + count[p]) % 26) + 65)
    
    cypher = ''
    i = 0
    fails = 0
    for c in txt:
        remember = i
        while dics[i // 26][i % 26] != c:
            i = (i + 1) % (26 ** 2)
            if remember == i:
                fails += 1
                break
        cypher += "(%s,%s), " % (i // 26, i % 26)
    cypher = cypher[:-2]
    return cypher, fails

def dec(txt: str, key : list, point : list):
    abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    dics = [list(map(lambda x: (ord(x) + key[i] - 65) % 26, list(abc)[i:] + list(abc)[:i])) for i in range(26)]
    for i in range(26):
        for j in range(26):
            p = (i - point[0], j - point[1])
            if p not in count:
                count[p] = 0
            dics[i][j] = chr(((dics[i][j] + count[p]) % 26) + 65)
    
    actual = list(map(eval, txt.split(", ")))
    plaintxt = ''
    for c in actual:
        plaintxt += dics[c[0]][c[1]]
    return plaintxt

class gammaEnc(Resource):
    def post(self):
        args = gamma_enc_parser.parse_args()
        entry = args['text']
        key = args['key']
        point = args['point']
        cypher, fails = enc(entry, key, point)
        return {"output": cypher, "percentageSuccess": (len(entry) - fails) / len(entry)}


class gammaDec(Resource):
    def post(self):
        args = gamma_dec_parser.parse_args()
        entry = args['text']
        key = args['key']
        point = args['point']
        plaintext = dec(entry, key, point)
        return {"output": plaintext}