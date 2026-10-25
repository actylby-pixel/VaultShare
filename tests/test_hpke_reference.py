"""HPKE 套件的独立参考实现交叉对测。

为什么没有直接跑 RFC 9180 附录 A 的测试向量
============================================
附录 A.1.1（以及 A.2/A.3）的向量都带有**非空 AAD**（例如 ``Count-0``）。
``cryptography`` 50.0.2 的 ``hpke.Suite.encrypt/decrypt`` 只接受 ``info``，
没有 ``aad`` 参数，因此无法逐字节复现这些向量；把 AAD 塞进 ``info`` 会得到
完全不同的密文。这是本协议的已知偏差（见 ``docs/PROTOCOL.md``），不能靠
“两个模块互相能解开”来掩盖。

这里做的替代验证：
* 按 RFC 9180 的定义（DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
  AES-128-GCM，Base 模式，空 AAD）用 ``X25519PrivateKey.exchange``、
  ``HKDF``、``AESGCM`` 独立拼出封装/解封装与 key schedule；
* 与 ``vaultshare.crypto.hpke`` 双向互测。这能发现套件参数、标签、
  长度、suite_id、密钥派生顺序等错误，且不依赖官方向量文件。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import support  # noqa: E402,F401

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from vaultshare.crypto import hpke  # noqa: E402

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0001
_KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (
    b"HPKE"
    + KEM_ID.to_bytes(2, "big")
    + KDF_ID.to_bytes(2, "big")
    + AEAD_ID.to_bytes(2, "big")
)


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM)。空 salt 等价于 32 个零字节
    # （HMAC 会把短 key 补零到 block size）。
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # 注意：cryptography 的 HKDF 类总是 extract+expand，不能直接用来做 Expand。
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(
    suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    return _hkdf_expand(
        prk, _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info, length
    )


def _dh(sk: bytes, pk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).exchange(
        X25519PublicKey.from_public_bytes(pk)
    )


def _public(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()


def _shared_secret(sk: bytes, peer_pk: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(_KEM_SUITE_ID, b"", b"eae_prk", _dh(sk, peer_pk))
    return _labeled_expand(
        _KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, 32
    )


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(_HPKE_SUITE_ID, secret, b"key", context, 16)
    nonce = _labeled_expand(_HPKE_SUITE_ID, secret, b"base_nonce", context, 12)
    return key, nonce


def reference_seal(recipient_public: bytes, plaintext: bytes, info: bytes) -> bytes:
    sk_e, pk_e = hpke.generate_keypair()
    shared = _shared_secret(sk_e, recipient_public, pk_e + recipient_public)
    key, nonce = _key_schedule(shared, info)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"")  # 空 AAD
    return pk_e + ciphertext


def reference_open(sk_r: bytes, wrapped: bytes, info: bytes) -> bytes:
    pk_e, ciphertext = wrapped[:32], wrapped[32:]
    shared = _shared_secret(sk_r, pk_e, pk_e + _public(sk_r))
    key, nonce = _key_schedule(shared, info)
    # AESGCM 解密同样使用空 AAD，seq=0。
    return AESGCM(key).decrypt(nonce, ciphertext, b"")


class ReferenceHpkeTests(unittest.TestCase):
    def test_reference_opens_library_seal(self) -> None:
        for size in (0, 1, 32, 129):
            sk_r, pk_r = hpke.generate_keypair()
            info = os.urandom(37)
            plaintext = os.urandom(size)
            wrapped = hpke.seal(pk_r, plaintext, info)
            self.assertEqual(reference_open(sk_r, wrapped, info), plaintext)

    def test_library_opens_reference_seal(self) -> None:
        for size in (0, 1, 32, 129):
            sk_r, pk_r = hpke.generate_keypair()
            info = os.urandom(37)
            plaintext = os.urandom(size)
            wrapped = reference_seal(pk_r, plaintext, info)
            self.assertEqual(hpke.open_sealed(sk_r, wrapped, info), plaintext)

    def test_reference_enforces_aad_and_nonce_binding(self) -> None:
        sk_r, pk_r = hpke.generate_keypair()
        info = b"info"
        wrapped = reference_seal(pk_r, b"payload", info)
        wrong_info = b"inf0"
        shared = _shared_secret(sk_r, wrapped[:32], wrapped[:32] + _public(sk_r))
        key, nonce = _key_schedule(shared, wrong_info)
        with self.assertRaises(InvalidTag):
            AESGCM(key).decrypt(nonce, wrapped[32:], b"")

    def test_lengths_match_wire_format(self) -> None:
        sk_r, pk_r = hpke.generate_keypair()
        wrapped = hpke.seal(pk_r, b"x" * 100, b"info")
        self.assertEqual(len(wrapped), hpke.ENC_LEN + 100 + hpke.TAG_LEN)
        enc, ct = hpke.split_wrap(wrapped)
        self.assertEqual(hpke.join_wrap(enc, ct), wrapped)


if __name__ == "__main__":
    unittest.main()
