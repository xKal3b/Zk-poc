# zkpoc_ref.py
from __future__ import annotations
import base64, dataclasses, hashlib, hmac, json, math, os, struct, zlib
from typing import List, Tuple, Optional

# ---------- helpers ----------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    layer = [leaf for leaf in leaves]
    while len(layer) > 1:
        nxt = []
        it = iter(layer)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                b = a
            nxt.append(sha256(a + b))
        layer = nxt
    return layer[0]

def chunk_bytes(b: bytes, sz: int) -> List[bytes]:
    if sz <= 0:
        raise ValueError("ChunkSize must be > 0")
    return [b[i:i+sz] for i in range(0, len(b), sz)] or [b""]

# ---------- codec params ----------
@dataclasses.dataclass(frozen=True)
class CodecParams:
    id: str = "DEFLATE"
    version: str = "1"
    level: int = 9
    strategy: int = zlib.Z_DEFAULT_STRATEGY
    wbits: int = 15        # raw DEFLATE: -15; zlib+deflate: 15; (we use zlib wrapper for broader compat)
    memLevel: int = 8
    dict_len: int = 32768  # zlib recommended max

# ---------- deterministic codec (zlib/DEFLATE + derived dictionary) ----------
def derive_dictionary(h_f: bytes, dict_len: int) -> bytes:
    # Expand from H(F) into a deterministic dictionary (pseudo HKDF)
    out = b""
    counter = 1
    while len(out) < dict_len:
        out += sha256(h_f + counter.to_bytes(4, "big"))
        counter += 1
    return out[:dict_len]

def compress_deterministic(data: bytes, params: CodecParams) -> Tuple[bytes, bytes]:
    h_f = sha256(data)
    zdict = derive_dictionary(h_f, params.dict_len)
    comp = zlib.compressobj(level=params.level, method=zlib.DEFLATED,
                            wbits=params.wbits, memLevel=params.memLevel,
                            strategy=params.strategy, zdict=zdict)
    out = comp.compress(data) + comp.flush()
    return out, zdict

def decompress_deterministic(c_bytes: bytes, params: CodecParams, zdict: bytes) -> bytes:
    decomp = zlib.decompressobj(wbits=params.wbits, zdict=zdict)
    out = decomp.decompress(c_bytes) + decomp.flush()
    return out

# ---------- commit / proof structures ----------
@dataclasses.dataclass
class Commit:
    codec: CodecParams
    chunk_size: int
    h_f_b64: str
    h_cf_b64: str
    dict_hash_b64: str
    merkle_root_b64: str
    chunk_hashes_b64: List[str]
    proof_kind: str
    proof_sig_b64: str

    def to_json(self) -> str:
        d = dataclasses.asdict(self)
        # codec isn't JSON-serializable by default; serialize explicitly
        d["codec"] = dataclasses.asdict(self.codec)
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "Commit":
        d = json.loads(s)
        codec = CodecParams(**d["codec"])
        return Commit(codec=codec,
                      chunk_size=d["chunk_size"],
                      h_f_b64=d["h_f_b64"],
                      h_cf_b64=d["h_cf_b64"],
                      dict_hash_b64=d["dict_hash_b64"],
                      merkle_root_b64=d["merkle_root_b64"],
                      chunk_hashes_b64=d["chunk_hashes_b64"],
                      proof_kind=d["proof_kind"],
                      proof_sig_b64=d["proof_sig_b64"])

# ---------- mock "ZK backend" = signed transcript (swap later for real ZK) ----------
class TranscriptProver:
    def __init__(self, secret: bytes):
        self.secret = secret

    def _transcript(self, codec: CodecParams, chunk_size: int, h_f: bytes,
                    h_cf: bytes, dict_hash: bytes, mroot: bytes) -> bytes:
        # domain separation + canonical encode
        parts = [
            b"zkPoC-v1",
            f"{codec.id}:{codec.version}:{codec.level}:{codec.strategy}:{codec.wbits}:{codec.memLevel}:{codec.dict_len}".encode(),
            struct.pack(">I", chunk_size),
            h_f, h_cf, dict_hash, mroot
        ]
        return sha256(b"||".join(parts))

    def prove(self, codec: CodecParams, chunk_size: int, h_f: bytes,
              h_cf: bytes, dict_hash: bytes, mroot: bytes) -> bytes:
        t = self._transcript(codec, chunk_size, h_f, h_cf, dict_hash, mroot)
        return hmac.new(self.secret, t, hashlib.sha256).digest()

    def verify(self, codec: CodecParams, chunk_size: int, h_f: bytes,
               h_cf: bytes, dict_hash: bytes, mroot: bytes, sig: bytes) -> bool:
        t = self._transcript(codec, chunk_size, h_f, h_cf, dict_hash, mroot)
        exp = hmac.new(self.secret, t, hashlib.sha256).digest()
        return hmac.compare_digest(exp, sig)

# ---------- high-level zkPoC pipeline ----------
class ZkPoC:
    def __init__(self, codec: CodecParams = CodecParams(),
                 chunk_size: int = 64 * 1024,
                 prover: Optional[TranscriptProver] = None):
        self.codec = codec
        self.chunk_size = chunk_size
        # In real use, replace TranscriptProver with actual ZK backend wrapper
        self.prover = prover or TranscriptProver(secret=os.urandom(32))

    def prove(self, F: bytes) -> Tuple[Commit, bytes, bytes]:
        h_f = sha256(F)
        C_F, zdict = compress_deterministic(F, self.codec)
        h_cf = sha256(C_F)
        dict_hash = sha256(zdict)

        chunks = chunk_bytes(C_F, self.chunk_size)
        h_chunks = [sha256(ch) for ch in chunks]
        mroot = merkle_root(h_chunks)

        sig = self.prover.prove(self.codec, self.chunk_size, h_f, h_cf, dict_hash, mroot)
        commit = Commit(
            codec=self.codec,
            chunk_size=self.chunk_size,
            h_f_b64=b64(h_f),
            h_cf_b64=b64(h_cf),
            dict_hash_b64=b64(dict_hash),
            merkle_root_b64=b64(mroot),
            chunk_hashes_b64=[b64(h) for h in h_chunks],
            proof_kind="transcript-hmac",  # placeholder until ZK backend
            proof_sig_b64=b64(sig),
        )
        return commit, C_F, zdict

    def verify(self, commit: Commit, C_F: bytes, zdict: bytes, strong: bool = True) -> bool:
        # re-compute everything deterministically
        h_cf = sha256(C_F)
        if b64(h_cf) != commit.h_cf_b64:
            return False

        dict_hash = sha256(zdict)
        if b64(dict_hash) != commit.dict_hash_b64:
            return False

        chunks = chunk_bytes(C_F, commit.chunk_size)
        h_chunks = [sha256(ch) for ch in chunks]
        mroot = merkle_root(h_chunks)
        if b64(mroot) != commit.merkle_root_b64:
            return False

        # Verify transcript signature (mock)
        ok_sig = self.prover.verify(commit.codec, commit.chunk_size,
                                    from_b64(commit.h_f_b64),
                                    from_b64(commit.h_cf_b64),
                                    from_b64(commit.dict_hash_b64),
                                    from_b64(commit.merkle_root_b64),
                                    from_b64(commit.proof_sig_b64))
        if not ok_sig:
            return False

        # Optional "strong" check for credibility in demos: actually decompress and compare H(F)
        if strong:
            F_prime = decompress_deterministic(C_F, commit.codec, zdict)
            if b64(sha256(F_prime)) != commit.h_f_b64:
                return False

        return True

# ---------- quick self-test ----------
if __name__ == "__main__":
    import sys
    data = b"zkPoC demo: " + os.urandom(1024 * 4) + b" end."
    zkpoc = ZkPoC()
    commit, C_F, zdict = zkpoc.prove(data)

    ok = zkpoc.verify(commit, C_F, zdict, strong=True)
    print("verify(ok):", ok)

    # tamper: flip a bit in compressed data
    bad = bytearray(C_F)
    if len(bad) > 10:
        bad[10] ^= 0x01
    ok2 = zkpoc.verify(commit, bytes(bad), zdict, strong=False)
    print("verify(tampered):", ok2)
