from flask_restful import Resource, reqparse
from random import randint
import base64
from sys import path

if "../common" not in path:
    path.append("../common")

from common import utils


PRIME = 2 ** 255 - 19

class CurvePoint():
    def __init__(self, x, y):
        self.value = (x, y)

    def __add__(self, other):
        x1, y1 = self.value
        x2, y2 = other.value
        if x1 == x2 and y1 == -y2 % PRIME:
            return BASE_POINT
        if x1 == x2 and y1 == y2:
            lmb = ((3 * x1 ** 2 + 486662) * pow((2 * y1), -1, PRIME)) % PRIME
        else:
            lmb = ((y2 - y1) * pow((x2 - x1), -1, PRIME)) % PRIME
        x3 = (lmb ** 2 - x1 - x2) % PRIME
        y3 = (lmb * (x1 - x3) - y1) % PRIME
        return CurvePoint(x3, y3)

    def int_mul(self, k: int):
        value = self
        for _ in range(k - 1):
            value = value + self
        return value

BASE_POINT = CurvePoint(
    9,
    14781619447589544791020593568409986887264606134616475288964881837755586237401
)

menezes_enc_parser = utils.enc_parser_keyless()
menezes_dec_parser = reqparse.RequestParser()
menezes_dec_parser.add_argument(
    "ciphertext",
    type=str,
    required=True,
    help="argument is required",
)

menezes_dec_parser.add_argument(
    "key",
    type=str,
    required=True,
    help="argument is required",
)

class MenezesEnc(Resource):
    def post(self):
        args = menezes_enc_parser.parse_args()
        plaintext = args["plaintext"]
        plaintext = get_values(plaintext)
        alpha = BASE_POINT.int_mul(randint(2, 100))
        a = randint(1, 256)
        beta = alpha.int_mul(a)
        ciphertext = []
        for x1, x2 in plaintext:
            k = randint(1, 256)
            y0 = alpha.int_mul(k)
            c1, c2 = beta.int_mul(k).value
            y1 = (c1 * x1) % PRIME
            y2 = (c2 * x2) % PRIME
            ciphertext.append((y0, y1, y2))
        with open(utils.FILEPATH + "menezes_ciphertext.txt", "w") as f:
            for y0, y1, y2 in ciphertext:
                f.write(f"{y0.value[0]} {y0.value[1]} {y1} {y2}\n")
        with open(utils.FILEPATH + "menezes_key.txt", "w") as f:
            for value in (a,):
                f.write(f"{value}\n")
        with open(utils.FILEPATH + "menezes_ciphertext.txt", "rb") as ciphertext:
            ciphertext = base64.b64encode(ciphertext.read()).decode()
        with open(utils.FILEPATH + "menezes_key.txt", "rb") as key:
            key = base64.b64encode(key.read()).decode()
        return {"ciphertext": ciphertext, "key": key}


class MenezesDec(Resource):
    def post(self):
        args = menezes_dec_parser.parse_args()
        ciphertext = base64.b64decode(args["ciphertext"])
        key = base64.b64decode(args["key"])
        ciphertext = list(map(str.split, filter(lambda x: len(x), ciphertext.decode().split('\r\n'))))
        ciphertext = [list(map(int, sublist)) for sublist in ciphertext]
        ciphertext = list(map(lambda x: (CurvePoint(x[0], x[1]), x[2], x[3]), ciphertext))
        key = list(map(int, filter(lambda x: len(x), key.decode().split('\r\n'))))
        a = int(key[0])
        plaintext = []
        for y0, y1, y2 in ciphertext:
            c1, c2 = y0.int_mul(a).value
            x = ((y1 * pow(c1, -1, PRIME)) % PRIME, (y2 * pow(c2, -1, PRIME)) % PRIME)
            plaintext.append(x)
        plaintext = get_text(plaintext)
        return {"plaintext": plaintext}

def get_values(text: str):
    text += "a" * (4 - (len(text) % 4))
    values = []
    for chunk in range (0, len(text) // 4):
        macro_chunk = text[chunk * 4: (chunk + 1) * 4]
        micro_chunk_a = macro_chunk[0: 2]
        micro_chunk_b = macro_chunk[2: 4]
        value_a = 0
        for i, c in enumerate(micro_chunk_a):
            value_a += utils.ascci_code(c) * (26 ** i)
        value_b = 0
        for i, c in enumerate(micro_chunk_b):
            value_b += utils.ascci_code(c) * (26 ** i)
        values.append((value_a, value_b))
    return values

def get_text(values):
    text = ""
    for value in values:
        text += get_text_chunk(value[0])
        text += get_text_chunk(value[1])
    return text

def get_text_chunk(n):
    if n == 0:
        return "aa"
    chunk = []
    while n:
        chunk.append(int(n % 26))
        n //= 26
    chunk = "".join(map(utils.chr_low, chunk))
    #chunk += "a" * (2 - (len(chunk) % 2))
    return chunk