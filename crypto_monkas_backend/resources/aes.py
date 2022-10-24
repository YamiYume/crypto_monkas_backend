from Crypto.Cipher import AES
from flask_restful import Resource, abort
import numpy as np
from PIL import Image
from sys import path, version_info
import base64
from common import utils

def aes_key(key):
    mode, iv, key = key.split(", ")
    key = bytes(map(int, key.split()))
    return (mode, bytes.fromhex(iv), key)


def valid_format(name: str) -> bool:
    name = name.split(".")
    return name[-1] in ["jpg", "png"]

modes = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB, 'OFB': AES.MODE_OFB, 'CTR': AES.MODE_CTR}
aes_enc_parser = utils.file_parser()

aes_dec_parser = utils.file_parser()

class AESEnc(Resource):
    def post(self, filename: str, key: str):
        try:
            mode, iv, key = aes_key(key)
        except ValueError as error:
            abort(400, message=error)
        if not valid_format(filename):
            abort(400, message="Unvalid File Format")
        args = aes_enc_parser.parse_args()
        image_file = args["file"]
        image_file.save(utils.FILEPATH + filename)
        self.encryption(filename, key, iv, mode)
        with open(utils.FILEPATH + "encimg" + filename, "rb") as ciphertext:
            ciphertext = base64.b64encode(ciphertext.read()).decode()
        return {"ciphertext": ciphertext}

    @staticmethod
    def encryption(filename: str, key: bytes, iv : bytes, mode : str) -> str:
        image = Image.open(utils.FILEPATH + filename)
        height, width = image.size
        dimensions = (height // 16 * 16, width // 16 * 16)
        image = image.resize(dimensions)
        image = np.array(image)
        if mode in ['ECB', 'CTR']:
            encriptor = AES.new(key, modes[mode])
        else:
            encriptor = AES.new(key, modes[mode], iv=iv)
        for channel in range(3):
            for j in range(image.shape[1]):
                image[:, j, channel] = list(map(int, encriptor.encrypt(bytes(image[:, j, channel]))))
        image = Image.fromarray(image)
        image.save(utils.FILEPATH + "encimg" + filename)


class AESDec(Resource):
    def post(self, filename: str, key: str):
        try:
            mode, iv, key = aes_key(key)
        except ValueError as error:
            abort(400, message=error)
        if not valid_format(filename):
            abort(400, message="Unvalid File Format")
        args = aes_dec_parser.parse_args()
        image_file = args["file"]
        image_file.save(utils.FILEPATH + filename)
        self.decryption(filename, key, iv, mode)
        with open(utils.FILEPATH + "decimg" + filename, "rb") as ciphertext:
            ciphertext = base64.b64encode(ciphertext.read()).decode()
        return {"ciphertext": ciphertext}

    @staticmethod
    def decryption(filename: str, key: bytes, iv:bytes, mode:str) -> str:
        image = Image.open(utils.FILEPATH + filename)
        height, width = image.size
        dimensions = (height // 8 * 8, width // 8 * 8)
        image = image.resize(dimensions)
        image = np.array(image)
        if mode in ['ECB', 'CTR']:
            decriptor = AES.new(key, modes[mode])
        else:
            decriptor = AES.new(key, modes[mode], iv=iv)
        for channel in range(3):
            for j in range(image.shape[1]):
                image[:, j, channel] = list(map(int, decriptor.encrypt(bytes(image[:, j, channel]))))
        image = Image.fromarray(image)
        image.save(utils.FILEPATH + "decimg" + filename)