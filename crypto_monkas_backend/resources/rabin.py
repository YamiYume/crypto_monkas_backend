from flask_restful import Resource, reqparse
from random import randint
import base64
from sys import path

if "../common" not in path:
    path.append("../common")

from common import utils
from common import lazyutils

rabin_enc_parser = utils.enc_parser_keyless()
rabin_dec_parser = reqparse.RequestParser()
rabin_dec_parser.add_argument(
    "ciphertext",
    type=str,
    required=True,
    help="argument is required",
)
rabin_dec_parser.add_argument(
    "key",
    type=str,
    required=True,
    help="argument is required",
)

class RabinEnc(Resource):
    def post(self):
        args = rabin_enc_parser.parse_args()
        plaintext = args["plaintext"]
        plaintext = get_values(plaintext)
        p = 0
        while p % 4 != 3:
            p = lazyutils.generate_prime_number()
        q = 0
        while q % 4 != 3:
            q = lazyutils.generate_prime_number()
        n = p * q
        b = randint(1, n)
        ciphertext = lazyutils.encRabin(plaintext, b, n)
        with open(utils.FILEPATH + "rabin_ciphertext.txt", "w") as f:
            for value in (ciphertext):
                f.write(f"{value}\n")
        with open(utils.FILEPATH + "rabin_key.txt", "w") as f:
            for value in (p, q, b):
                f.write(f"{value}\n")
        with open(utils.FILEPATH + "rabin_ciphertext.txt", "rb") as ciphertext:
            ciphertext = base64.b64encode(ciphertext.read()).decode()
        with open(utils.FILEPATH + "rabin_key.txt", "rb") as key:
            key = base64.b64encode(key.read()).decode()
        return {"ciphertext": ciphertext, "key": key}


class RabinDec(Resource):
    def post(self):
        args = rabin_dec_parser.parse_args()
        ciphertext = base64.b64decode(args["ciphertext"])
        key = base64.b64decode(args["key"])
        ciphertext = list(map(int, filter(lambda x: len(x), ciphertext.decode().split('\r\n'))))
        key = list(map(int, filter(lambda x: len(x), key.decode().split('\r\n'))))
        p, q, b = key
        plaintexts = lazyutils.decRabin(ciphertext, b, p, q)
        for i in range(0, len(plaintexts)):
            plaintexts[i] = list(filter(lambda x: x < 456976, plaintexts[i]))
            print(plaintexts[i])
            plaintexts[i] = get_text(plaintexts[i])
        plaintext = "".join(plaintexts)
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