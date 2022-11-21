from flask import Flask
import os
from flask_cors import CORS
from flask_restful import Api
from resources.shift import ShiftEnc, ShiftDec, ShiftAtk
from resources.afin import AfinAtk, AfinDec, AfinEnc
from resources.substitution import SubsEnc, SubsDec, SubsAtk
from resources.vigenere import VigEnc, VigDec, VigAtk
from resources.permutation import PermEnc, PermDec
from resources.hill import HillEnc, HillDec
from resources.TDES import TDESEnc, TDESDec
from resources.SDES import SDESEnc, SDESDec
from resources.gamma import gammaEnc, gammaDec
from resources.aes import AESEnc, AESDec
from resources.rabin import RabinEnc, RabinDec
from resources.rsa import RSAEnc, RSADec
from resources.elgamal import GamalEnc, GamalDec
from resources.menezes import MenezesEnc, MenezesDec
from common import utils

if os.path.exists(utils.FILEPATH):
    for file_path in os.listdir(utils.FILEPATH):
        try:
            os.unlink(utils.FILEPATH + file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))
else:
    os.makedirs(utils.FILEPATH)

app = Flask(__name__)
CORS(app)
app.config["UPLOAD FOLDER"] = utils.FILEPATH

api = Api(app)

api.add_resource(ShiftEnc, "/shift/enc")
api.add_resource(ShiftDec, "/shift/dec")
api.add_resource(ShiftAtk, "/shift/atk")
api.add_resource(AfinEnc, "/afin/enc")
api.add_resource(AfinDec, "/afin/dec")
api.add_resource(AfinAtk, "/afin/atk")
api.add_resource(SubsEnc, "/subs/enc")
api.add_resource(SubsDec, "/subs/dec")
api.add_resource(SubsAtk, "/subs/atk")
api.add_resource(VigEnc, "/vig/enc")
api.add_resource(VigDec, "/vig/dec")
api.add_resource(VigAtk, "/vig/atk")
api.add_resource(PermEnc, "/perm/enc")
api.add_resource(PermDec, "/perm/dec")
api.add_resource(HillEnc, "/hill/enc")
api.add_resource(HillDec, "/hill/dec")
api.add_resource(TDESEnc, "/tdes/enc")
api.add_resource(TDESDec, "/tdes/dec")
api.add_resource(SDESEnc, "/sdes/enc")
api.add_resource(SDESDec, "/sdes/dec")
api.add_resource(gammaEnc, "/gamma/enc")
api.add_resource(gammaDec, "/gamma/dec")
api.add_resource(AESEnc, "/aes/enc")
api.add_resource(AESDec, "/aes/dec")
api.add_resource(RabinEnc, "/rabin/enc")
api.add_resource(RabinDec, "/rabin/dec")
api.add_resource(RSAEnc, "/rsa/enc")
api.add_resource(RSADec, "/rsa/dec")
api.add_resource(GamalEnc, "/gamal/enc")
api.add_resource(GamalDec, "/gamal/dec")
api.add_resource(MenezesEnc, "/menezes/enc")
api.add_resource(MenezesDec, "/menezes/dec")

if __name__ == "__main__":
    
    app.run(debug=True)
