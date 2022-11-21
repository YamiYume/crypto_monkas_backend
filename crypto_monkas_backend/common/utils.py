from string import ascii_lowercase, ascii_uppercase
from collections import Counter
from flask_restful import reqparse
import os

MONOFREQ = {
    "e": 12.70,
    "t": 9.06,
    "a": 8.17,
    "o": 7.51,
    "i": 6.97,
    "n": 6.75,
    "s": 6.33,
    "h": 6.09,
    "r": 5.99,
    "d": 4.25,
    "l": 4.03,
    "c": 2.78,
    "u": 2.76,
    "m": 2.41,
    "w": 2.36,
    "f": 2.23,
    "g": 2.02,
    "y": 1.97,
    "p": 1.93,
    "b": 1.29,
    "v": 0.98,
    "k": 0.77,
    "j": 0.15,
    "x": 0.15,
    "q": 0.10,
    "z": 0.07,
}

BIFREQ = {
    "th": 3.56,
    "of": 1.17,
    "io": 0.83,
    "he": 3.07,
    "ed": 1.17,
    "le": 0.83,
    "in": 2.43,
    "is": 1.13,
    "ve": 0.83,
    "er": 2.05,
    "it": 1.12,
    "co": 0.79,
    "an": 1.99,
    "al": 1.09,
    "me": 0.79,
    "re": 1.85,
    "ar": 1.07,
    "de": 0.76,
    "on": 1.76,
    "st": 1.05,
    "hi": 0.76,
    "at": 1.49,
    "to": 1.05,
    "ri": 0.73,
    "en": 1.45,
    "nt": 1.04,
    "ro": 0.73,
    "nd": 1.35,
    "ng": 0.95,
    "ic": 0.70,
    "ti": 1.34,
    "se": 0.93,
    "ne": 0.69,
    "es": 1.34,
    "ha": 0.93,
    "ea": 0.69,
    "or": 1.28,
    "as": 0.87,
    "ra": 0.69,
    "te": 1.20,
    "ou": 0.87,
    "ce": 0.65,
}

FILEPATH = os.getcwd() + "/resources/tmp/"


def mono_diff_rank(word: str) -> float:
    w_char_rfreq = {c: f / len(word) for c, f in Counter(word).items()}
    mean_error = 0
    for char, e_char_rfreq in MONOFREQ.items():
        mean_error += abs(e_char_rfreq - w_char_rfreq.get(char, 0))
    mean_error /= 26
    return mean_error


def bi_diff_rank(word: str) -> float:
    pairs = [word[i] + word[i+1] for i in range(len(word) - 1)]
    w_bi_rfreq = {
        "".join(c): f / (len(word) - 1) for c, f in Counter(pairs).items()
    }
    mean_error = 0
    for bigraph, e_bi_rfreq in BIFREQ.items():
        mean_error += abs(e_bi_rfreq - w_bi_rfreq.get(bigraph, 0))
    mean_error /= len(BIFREQ)
    return mean_error


def diff_rank(word: str) -> float:
    return mono_diff_rank(word) + bi_diff_rank(word)


def coincidence_index_rank(word: str) -> float:
    word = word.lower()
    freq = Counter(word)
    ic = 0
    for key in ascii_lowercase:
        ni = freq.get(key, 0)
        ic += ni
    ic /= len(word) * (len(word) - 1)
    return abs(0.067 - ic)


def plaintext(text: str) -> str:
    text = text.lower()
    text = "".join(filter(lambda c: c.isalpha(), text))
    return text


def ciphertext(text: str) -> str:
    text = text.upper()
    text = "".join(filter(lambda c: c.isalpha(), text))
    return text


def head_value(value: str) -> int:
    value = value.split(" ")
    try:
        value = int(value[0])
    except ValueError:
        raise ValueError("Argument can't be parse as integer")
    return value


def ascci_code(c: str) -> int:
    if len(c) > 1:
        raise ValueError("must be single character")
    c = c.lower()
    index = ascii_lowercase.index(c)
    return index


def chr_low(x: int) -> str:
    x = x % 26
    return ascii_lowercase[x]


def chr_up(x: int) -> str:
    x = x % 26
    return ascii_uppercase[x]

def enc_parser(key_type: callable) -> reqparse.RequestParser:
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "plaintext", type=plaintext, required=True, help="plaintext is required"
    )
    new_parser.add_argument(
        "key", type=key_type, required=True, help="unvalid argument: {error_msg}"
    )
    return new_parser

def enc_parser_keyless() -> reqparse.RequestParser:
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "plaintext", type=plaintext, required=True, help="plaintext is required"
    )
    return new_parser


def dec_parser(key_type: callable) -> reqparse.RequestParser:
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "ciphertext", type=ciphertext, required=True, help="ciphertext is required"
    )
    new_parser.add_argument(
        "key", type=key_type, required=True, help="unvalid argument: {error_msg}"
    )
    return new_parser

def file_parser(key_type: callable):
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "file",
        type=str,
        required=True,
        help="argument is required",
    )
    new_parser.add_argument(
        "key",
        type=key_type,
        required=True,
        help="argument is required",
    )
    return new_parser

def sdes_parser(key_type: callable):
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "text", type=str, required=True, help="input text is required"
    )
    new_parser.add_argument(
        "key", type=key_type, required=True, help="unvalid argument: {error_msg}"
    )
    return new_parser

def gamma_parser(key_type: callable, key_point: callable):
    new_parser = reqparse.RequestParser()
    new_parser.add_argument(
        "text", type=str, required=True, help="input text is required"
    )
    new_parser.add_argument(
        "point", type=key_point, required=True, help="Location of the origint required"
    )
    new_parser.add_argument(
        "key", type=key_type, required=True, help="unvalid argument: {error_msg}"
    )
    return new_parser