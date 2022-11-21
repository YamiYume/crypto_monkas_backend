from flask_restful import Resource, reqparse
from random import randint
from more_itertools import grouper
from typing import List, Tuple
from sys import path

path.append("../common")

from common import utils


def perm_key(key: str) -> List[int]:
    key = "".join([c if (c.isdecimal() or c.isspace()) else "" for c in key])
    key = key.split()
    if len(key) == 0:
        raise ValueError("No valid argument was provided")
    key = list(map(int, key))
    if max(key) != len(key) or min(key) != 1:
        raise ValueError(
            "Argument must contain only the integers from 1 to it's lenght"
        )
    if len(key) != len(set(key)):
        raise ValueError("Argument includes repeated integers")
    return key


perm_enc_parser = utils.enc_parser(perm_key)

perm_dec_parser = utils.dec_parser(perm_key)

perm_atk_parser = reqparse.RequestParser()
perm_atk_parser.add_argument(
    "ciphertext", type=utils.ciphertext, required=True, help="ciphertext is required"
)
perm_atk_parser.add_argument(
    "head", type=utils.head_value, required=True, help="unvalid_argument: {error_msg}"
)


class PermEnc(Resource):
    def post(self):
        args = perm_enc_parser.parse_args()
        plaintext = args["plaintext"]
        key = args["key"]
        ciphertext = self.encryption(plaintext, key)
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(plaintext: str, key: List[int]) -> str:
        missing = len(key) - (len(plaintext) % len(key))
        plaintext += "".join(utils.chr_low(randint(0, 25)) for _ in range(missing))
        ciphertext = ""
        for chunk in grouper(plaintext, len(key), incomplete="strict"):
            for k in key:
                ciphertext += chunk[k - 1]
        ciphertext = ciphertext.upper()
        return ciphertext


class PermDec(Resource):
    def post(self):
        args = perm_dec_parser.parse_args()
        ciphertext = args["ciphertext"]
        key = args["key"]
        plaintext = self.decryption(ciphertext, key)
        return {"plaintext": plaintext}

    @staticmethod
    def decryption(ciphertext: str, key: List[int]) -> str:
        missing = len(key) - (len(ciphertext) % len(key))
        ciphertext += "".join(utils.chr_low(randint(0, 25)) for _ in range(missing))
        plaintext = ""
        for chunk in grouper(ciphertext, len(key)):
            new_chunk = [None] * len(key)
            for c, k in zip(chunk, key):
                new_chunk[k - 1] = c
            plaintext += "".join(new_chunk)
        plaintext = plaintext.lower()
        return plaintext


class PermAtk(Resource):
    def post(self):
        args = perm_atk_parser.parse_args()
        ciphertext = args["ciphertext"]
        head = args["head"]
        plaintexts_attempts = self.attack(ciphertext)
        return {"plaintext_attempts": plaintexts_attempts[:head]}

    @staticmethod
    def attack(ciphertext: str) -> List[Tuple[str, int]]:
        plaintexts_attempts = []
        for key in range(26):
            plaintexts_attempts.append((PermDec.decryption(ciphertext, key), key))
        plaintexts_attempts.sort(key=lambda t: utils.diff_rank(t[0]))
        return plaintexts_attempts
