def buildJWKS(n: bytes, e:bytes, kid: str):
    return {"kty": "RSA", "kid": kid, "use": "sig", "e": str(e.decode('UTF-8')),
               "n": str(n.decode('UTF-8').rstrip("="))}
