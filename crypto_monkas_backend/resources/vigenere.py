from flask_restful import Resource, reqparse
from collections import Counter
from typing import List, Tuple
from more_itertools import triplewise
import numpy as np
from sys import path

if "../common" not in path:
    path.append("../common")

from common import utils
from .shift import ShiftAtk


def vig_key(key: str) -> List[int]:
    key = "".join([c if (c.isalpha() or c.isspace()) else "" for c in key])
    key = key.split()
    try:
        key = key[0]
    except IndexError:
        raise ValueError("No valid argument was provided")
    key = [utils.ascci_code(c) for c in key]

    return key


vig_enc_parser = utils.enc_parser(vig_key)

vig_dec_parser = utils.dec_parser(vig_key)

vig_atk_parser = reqparse.RequestParser()
vig_atk_parser.add_argument(
    "ciphertext", type=utils.ciphertext, required=True, help="ciphertext is required"
)
vig_atk_parser.add_argument(
    "head", type=utils.head_value, required=True, help="unvalid_argument: {error_msg}"
)


class VigEnc(Resource):
    def post(self):
        args = vig_enc_parser.parse_args()
        plaintext = args["plaintext"]
        key = args["key"]
        ciphertext = self.encryption(plaintext, key)
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(plaintext: str, key: List[int]) -> str:
        ciphertext = ""
        for i, c in enumerate(plaintext):
            ciphertext += utils.chr_up(utils.ascci_code(c) + key[i % len(key)])
        return ciphertext


class VigDec(Resource):
    def post(self):
        args = vig_dec_parser.parse_args()
        ciphertext = args["ciphertext"]
        key = args["key"]
        plaintext = self.decryption(ciphertext, key)
        return {"plaintext": plaintext}

    @staticmethod
    def decryption(ciphertext: str, key: List[int]) -> str:
        plaintext = ""
        for i, c in enumerate(ciphertext):
            plaintext += utils.chr_low(utils.ascci_code(c) - key[i % len(key)])
        return plaintext


class VigAtk(Resource):
    def get(self):
        args = vig_atk_parser.parse_args()
        ciphertext = args["ciphertext"]
        head = args["head"]
        key_lenghts = self.key_lenghts(ciphertext, head)
        plaintext_attempts = self.attack(ciphertext, key_lenghts)
        return {"plaintext_attempts": plaintext_attempts}

    @staticmethod
    def attack(ciphertext: str, key_lenghts: List[int]) -> List[Tuple[str, str]]:
        plaintext_attempts = []
        for key_lenght in key_lenghts:
            key = []
            subciphertexts = (ciphertext[i::key_lenght] for i in range(key_lenght))
            for subciphertext in subciphertexts:
                key.append(ShiftAtk.attack(subciphertext)[0][1])
            key_str = "".join(map(utils.chr_up, key))
            plaintext_attempts.append((VigDec.decryption(ciphertext, key), key_str))
        return plaintext_attempts

    @staticmethod
    def key_lenghts(ciphertext: str, head: int) -> List[int]:
        cipher_sections = list(
            map(
                "".join,
                triplewise(ciphertext),
            )
        )
        counts = Counter(cipher_sections)
        repeated = [c for c, count in counts.items() if count > 1]
        distances = []
        for c in repeated:
            indexes = [i for i, value in enumerate(cipher_sections) if value == c]
            distance_candidates = [b - a for a, b in zip(indexes, indexes[1:])]
            mcd = np.gcd.reduce(distance_candidates)
            if mcd > 1:
                distances.append(mcd)
        key_lenghts = list(set(distances))
        key_lenghts.sort(key=lambda x: distances.count(x), reverse=True)
        return key_lenghts[:head]
