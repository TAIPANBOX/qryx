import hashlib


def digest(data: bytes) -> str:
    # SHA-1 is weak
    return hashlib.sha1(data).hexdigest()


def strong(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
