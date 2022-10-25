from flask_restful import Resource, reqparse
from typing import List
from collections import Counter
from sys import path

path.append("../common")

from common import utils


def subs_key(value: str) -> List[str]:
    value = value.upper()
    value = [c for c in value if c.isalpha()]
    if len(value) != 26:
        raise ValueError("Argument have a wrong lenght")
    if len(value) != len(set(value)):
        raise ValueError("Argument includes repeat letters")
    return value


subs_enc_parser = utils.enc_parser(subs_key)

subs_dec_parser = utils.dec_parser(subs_key)

subs_atk_parser = reqparse.RequestParser()
subs_atk_parser.add_argument(
    "ciphertext", type=utils.ciphertext, required=True, help="ciphertext is required"
)


class SubsEnc(Resource):
    def post(self):
        args = subs_enc_parser.parse_args()
        plaintext = args["plaintext"]
        key = args["key"]
        ciphertext = self.encryption(plaintext, key)
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(plaintext: str, key: List[str]) -> str:
        enc_map = {x: y for x, y in zip(utils.ascii_lowercase, key)}
        ciphertext = ""
        for c in plaintext:
            ciphertext += enc_map[c]
        return ciphertext


class SubsDec(Resource):
    def post(self):
        args = subs_dec_parser.parse_args()
        ciphertext = args["ciphertext"]
        key = args["key"]
        plaintext = self.decryption(ciphertext, key)
        return {"plaintext": plaintext}

    @staticmethod
    def decryption(ciphertext: str, key: List[str]) -> str:
        dec_map = {x: y for x, y in zip(key, utils.ascii_lowercase)}
        plaintext = ""
        for c in ciphertext:
            plaintext += dec_map[c]
        return plaintext


class SubsAtk(Resource):
    def post(self):
        args = subs_atk_parser.parse_args()
        ciphertext = args["ciphertext"]
        mono_counts = Counter(ciphertext)
        bi_counts = Counter(zip(ciphertext, ciphertext[1:]))
        return {
            "mono_letters": list(mono_counts.keys()),
            "mono_values": [x / len(ciphertext) for x in mono_counts.values()],
            "bi_letters": list(map("".join, bi_counts.keys())),
            "bi_values": [x / (len(ciphertext) - 1) for x in bi_counts.values()],
        }
