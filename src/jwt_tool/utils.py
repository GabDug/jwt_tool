"""Collection of utils functions, that do not use globals."""
import base64
import json

import re
from typing import Dict, Tuple, Any

from Cryptodome.PublicKey import RSA, ECC

from jwt_tool.constants import jwt_regex


def parse_dict_cookies(value: str)-> "Dict[str, Any]":
    cookiedict = {}
    for item in value.split(';'):
        item = item.strip()
        if not item:
            continue
        if '=' not in item:
            cookiedict[item] = None
            continue
        name, value = item.split('=', 1)
        cookiedict[name] = value
    return cookiedict


def strip_dict_cookies(value: str):
    cookiestring = ""
    for item in value.split(';'):
        if re.search(jwt_regex, item):
            continue
        else:
            cookiestring += "; "+item
        cookiestring = cookiestring.lstrip("; ")
    return cookiestring


def newRSAKeyPair() -> "Tuple[bytes, bytes]":
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey


def newECKeyPair() -> "Tuple[str, str]":
    new_key = ECC.generate(curve='P-256')
    pubkey = new_key.public_key().export_key(format="PEM")
    privKey = new_key.export_key(format="PEM")
    return pubkey, privKey


def genContents(headDict: Dict, paylDict: Dict) -> str:
    """
    Base64 encode JWT header and payload
    """
    newContents = encode_jwt_part(headDict)+"."  +encode_jwt_part(paylDict)
    return newContents.encode().decode('UTF-8')


def encode_jwt_part(payload_or_header: Dict) -> str:
    if payload_or_header == {}:
        return ""
    return base64.urlsafe_b64encode(json.dumps(payload_or_header,separators=(",",":")).encode()).decode('UTF-8').strip("=")


def unsafe_jwt_part(payload_or_header: Dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload_or_header,separators=(",",":")).encode()).decode('UTF-8').strip("=")


def checkNullSig(contents):
    jwtNull = contents.decode()+"."
    return jwtNull


def castInput(newInput):
    if "{" in str(newInput):
        try:
            jsonInput = json.loads(newInput)
            return jsonInput
        except ValueError:
            pass
    if "\"" in str(newInput):
        return newInput.strip("\"")
    elif newInput == "True" or newInput == "true":
        return True
    elif newInput == "False" or newInput == "false":
        return False
    elif newInput == "null":
        return None
    else:
        try:
            numInput = float(newInput)
            try:
                intInput = int(newInput)
                return intInput
            except:
                return numInput
        except:
            return str(newInput)
    return newInput
