from flask_restful import Resource, reqparse
from typing import List, Tuple
from sys import path

path.append("../common")

from common import utils


def shift_key(key: str) -> int:
    value = "".join([c if (c.isdecimal() or c.isspace()) else "" for c in key])
    value = value.split()
    try:
        value = int(value[0]) % 26
    except IndexError:
        raise ValueError("No argument was provided")
    except ValueError:
        raise ValueError("Argument can't be parse as integer")

    return value


shift_enc_parser = utils.enc_parser(shift_key)

shift_dec_parser = utils.dec_parser(shift_key)

shift_atk_parser = reqparse.RequestParser()
shift_atk_parser.add_argument(
    "ciphertext", type=utils.ciphertext, required=True, help="ciphertext is required"
)
shift_atk_parser.add_argument(
    "head", type=utils.head_value, required=True, help="unvalid_argument: {error_msg}"
)


class ShiftEnc(Resource):
    def get(self):
        args = shift_enc_parser.parse_args()
        plaintext = args["plaintext"]
        key = args["key"]
        ciphertext = self.encryption(plaintext, key)
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(plaintext: str, key: int) -> str:
        ciphertext = ""
        for c in plaintext:
            ciphertext += utils.chr_up(utils.ascci_code(c) + key)
        return ciphertext


class ShiftDec(Resource):
    def get(self):
        args = shift_dec_parser.parse_args()
        ciphertext = args["ciphertext"]
        key = args["key"]
        plaintext = self.decryption(ciphertext, key)
        return {"plaintext": plaintext}

    @staticmethod
    def decryption(ciphertext: str, key: int) -> str:
        plaintext = ""
        for c in ciphertext:
            plaintext += utils.chr_low(utils.ascci_code(c) - key)
        return plaintext


class ShiftAtk(Resource):
    def post(self):
        args = shift_atk_parser.parse_args()
        ciphertext = args["ciphertext"]
        head = args["head"]
        plaintexts_attempts = self.attack(ciphertext)
        return {"plaintext_attempts": plaintexts_attempts[:head]}

    @staticmethod
    def attack(ciphertext: str) -> List[Tuple[str, int]]:
        plaintexts_attempts = []
        for key in range(26):
            plaintexts_attempts.append((ShiftDec.decryption(ciphertext, key), key))
        plaintexts_attempts.sort(key=lambda t: utils.diff_rank(t[0]))
        return plaintexts_attempts
