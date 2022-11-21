#from array import array
#from ast import Str, match_case
#from difflib import Match
from Crypto.Cipher import DES3
from io import BytesIO
from flask_restful import Resource, abort
import numpy as np
from PIL import Image
from sys import path, version_info
import base64

path.append("../common")

from common import utils

modes = {'ECB': DES3.MODE_ECB, 'CBC': DES3.MODE_CBC, 'CFB': DES3.MODE_CFB, 'OFB': DES3.MODE_OFB, 'CTR': DES3.MODE_CTR}

def tdes_key(key: str):
    mode, iv, key = key.split(", ")
    key = bytes(map(int, key.split()))
    return (mode, bytes(map(int, iv.split())), key)


def valid_format(name: str) -> bool:
    name = name.split(".")
    return name[-1] in ["jpg", "png"]


tdes_enc_parser = utils.file_parser(tdes_key)

tdes_dec_parser = utils.file_parser(tdes_key)
    

class TDESEnc(Resource):
    def post(self):
        args = tdes_enc_parser.parse_args()
        mode, iv, key = args['key']
        image_file = BytesIO(base64.b64decode(args["file"]))
        image = Image.open(image_file)
        self.encryption(image, key, iv, mode)
        with open(utils.FILEPATH + "encimg.png", "rb") as ciphertext:
            output = base64.b64encode(ciphertext.read()).decode()
        return {"output": output}

    @staticmethod
    def encryption(image : Image, key: bytes, iv : bytes, mode : str) -> str:
        height, width = image.size
        dimensions = (height // 16 * 16, width // 16 * 16)
        image = image.resize(dimensions)
        image = np.array(image)
        if mode == 'ECB':
            encriptor = DES3.new(key, modes[mode])
        elif mode == 'CTR':
            encriptor = DES3.new(key, modes[mode], nonce=iv)
        else:
            encriptor = DES3.new(key, modes[mode], iv=iv)
        for channel in range(3):
            for j in range(image.shape[1]):
                image[:, j, channel] = list(map(int, encriptor.encrypt(bytes(image[:, j, channel]))))
        image = Image.fromarray(image)
        image.save(utils.FILEPATH + "encimg.png")


class TDESDec(Resource):
    def post(self):
        args = tdes_dec_parser.parse_args()
        mode, iv, key = args['key']
        image_file = BytesIO(base64.b64decode(args["file"]))
        image = Image.open(image_file)
        self.decryption(image, key, iv, mode)
        with open(utils.FILEPATH + "decimg.png", "rb") as ciphertext:
            output = base64.b64encode(ciphertext.read()).decode()
        return {"output": output}

    @staticmethod
    def decryption(image: Image, key: bytes, iv:bytes, mode:str) -> str:
        height, width = image.size
        dimensions = (height // 8 * 8, width // 8 * 8)
        image = image.resize(dimensions)
        image = np.array(image)
        if mode == 'ECB':
            decriptor = DES3.new(key, modes[mode])
        elif mode == 'CTR':
            decriptor = DES3.new(key, modes[mode], nonce=iv)
        else:
            decriptor = DES3.new(key, modes[mode], iv=iv)
        for channel in range(3):
            for j in range(image.shape[1]):
                image[:, j, channel] = list(map(int, decriptor.decrypt(bytes(image[:, j, channel]))))
        image = Image.fromarray(image)
        image.save(utils.FILEPATH + "decimg.png")
