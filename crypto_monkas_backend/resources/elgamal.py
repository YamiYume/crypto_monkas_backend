from flask_restful import Resource, reqparse
from random import randint
import base64
from sys import path

if "../common" not in path:
    path.append("../common")

from common import utils
from common import lazyutils

gamal_enc_parser = utils.enc_parser_keyless()
gamal_dec_parser = reqparse.RequestParser()
gamal_dec_parser.add_argument(
    "ciphertext",
    type=str,
    required=True,
    help="argument is required",
)
gamal_dec_parser.add_argument(
    "key",
    type=str,
    required=True,
    help="argument is required",
)

class GamalEnc(Resource):
    def post(self):
        args = gamal_enc_parser.parse_args()
        plaintext = args["plaintext"]
        plaintext = get_values(plaintext)
        p = lazyutils.generate_prime_number(length=64)
        a = randint(1, p)
        exp = lazyutils.generate_prime_number(length=16)
        while p % exp == 0:
            exp = lazyutils.generate_prime_number(length=16)
        b = a ** exp
        ciphertext = lazyutils.encGamal(plaintext, a, b, p)
        with open(utils.FILEPATH + "gamal_ciphertext.txt", "w") as f:
            for value in (ciphertext):
                f.write(f"{value[0]} {value[1]}\n")
        with open(utils.FILEPATH + "gamal_key.txt", "w") as f:
            for value in (a, exp, p):
                f.write(f"{value}\n")
        with open(utils.FILEPATH + "gamal_ciphertext.txt", "rb") as ciphertext:
            ciphertext = base64.b64encode(ciphertext.read()).decode()
        with open(utils.FILEPATH + "gamal_key.txt", "rb") as key:
            key = base64.b64encode(key.read()).decode()
        return {"ciphertext": ciphertext, "key": key}


class GamalDec(Resource):
    def post(self):
        args = gamal_dec_parser.parse_args()
        ciphertext = base64.b64decode(args["ciphertext"])
        key = base64.b64decode(args["key"])
        ciphertext = list(map(str.split, filter(lambda x: len(x), ciphertext.decode().split('\r\n'))))
        ciphertext = [(int(val[0]), int(val[1])) for val in ciphertext]
        key = list(map(int, filter(lambda x: len(x), key.decode().split('\r\n'))))
        a, exp, p = key
        plaintext = lazyutils.decGamal(ciphertext, a, exp, p)
        plaintext = get_text(plaintext)
        return {"plaintext": plaintext}


def get_values(text: str):
    text += "a" * (4 - (len(text) % 4))
    values = []
    for chunk in range (0, len(text) // 4):
        chunk = text[chunk * 4: (chunk + 1) * 4]
        value = 0
        for i, c in enumerate(chunk):
            value += utils.ascci_code(c) * (26 ** i)
        values.append(value)
    return values

def get_text(values):
    text = ""
    for value in values:
        text += get_text_chunk(value)
    return text

def get_text_chunk(n):
    if n == 0:
        return "aaaa"
    chunk = []
    while n:
        chunk.append(int(n % 26))
        n //= 26
    chunk = "".join(map(utils.chr_low, chunk))
    return chunk