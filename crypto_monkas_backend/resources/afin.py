from flask_restful import Resource, reqparse
from typing import List, Tuple
from itertools import product
from sys import path

if "../common" not in path:
    path.append("../common")

from common import utils


def afin_key(value: str) -> Tuple[int]:
    value = "".join([c if (c.isdecimal() or c.isspace()) else "" for c in value])
    value = value.split()
    try:
        value_a = int(value[0]) % 26
    except IndexError:
        raise ValueError("No A argument was provided")
    except ValueError:
        raise ValueError("A Argument can't be parse as integer")
    if value_a % 2 == 0 or value_a % 13 == 0:
        raise ValueError("Key is not invertible")
    try:
        value_b = int(value[1]) % 26
    except IndexError:
        raise ValueError("No B argument was provided")
    except ValueError:
        raise ValueError("B Argument can't be parse as integer")

    return (value_a, value_b)


afin_enc_parser = utils.enc_parser(afin_key)

afin_dec_parser = utils.dec_parser(afin_key)

afin_atk_parser = reqparse.RequestParser()
afin_atk_parser.add_argument(
    "ciphertext", type=utils.ciphertext, required=True, help="ciphertext is required"
)
afin_atk_parser.add_argument(
    "head", type=utils.head_value, required=True, help="unvalid_argument {error_msg}"
)


class AfinEnc(Resource):
    def post(self):
        args = afin_enc_parser.parse_args()
        plaintext = args["plaintext"]
        key = args["key"]
        ciphertext = self.encryption(plaintext, key)
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(plaintext: str, key: Tuple[int]) -> str:
        ciphertext = ""
        for c in plaintext:
            ciphertext += utils.chr_up(utils.ascci_code(c) * key[0] + key[1])
        return ciphertext


class AfinDec(Resource):
    def get(self):
        args = afin_dec_parser.parse_args()
        ciphertext = args["ciphertext"]
        key = args["key"]
        plaintext = self.decryption(ciphertext, key)
        return {"plaintext": plaintext}

    @staticmethod
    def decryption(ciphertext: str, key: Tuple[int]) -> str:
        plaintext = ""
        for c in ciphertext:
            plaintext += utils.chr_low(
                (utils.ascci_code(c) - key[1]) * pow(key[0], -1, 26)
            )
        return plaintext


class AfinAtk(Resource):
    def get(self):
        args = afin_atk_parser.parse_args()
        ciphertext = args["ciphertext"]
        head = args["head"]
        plaintext_attemps = self.attack(ciphertext)
        return {"plaintext_attemps": plaintext_attemps[:head]}

    @staticmethod
    def attack(ciphertext: str) -> List[Tuple[str, Tuple[int]]]:
        plaintext_attemps = []
        key_1 = [*range(26)]
        key_0 = filter(lambda x: x % 2 != 0 and x % 13 != 0, key_1)
        for key in product(key_0, key_1):
            plaintext_attemps.append((AfinDec.decryption(ciphertext, key), key))
        plaintext_attemps.sort(key=lambda t: utils.diff_rank(t[0]))
        return plaintext_attemps
