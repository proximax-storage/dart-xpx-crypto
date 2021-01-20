part of xpx_crypto;

// HashesSha3_256 return sha3 256 hash of byte
Uint8List HashesSha3_256(Uint8List b) {
  final hash = sha3.createSha3Digest(length: 32);
  return hash.process(b);
}

// HashesSha3_512 return sha3 512 hash of byte
Uint8List HashesSha3_512(Uint8List b) {
  final hash = sha3.createSha3Digest(length: 64);
  return hash.process(b);
}

// HashesRipemd160 return ripemd160 hash of byte
Uint8List HashesRipemd160(Uint8List b) {
  final hash = sha3.RIPEMD();
  final Uint8List sk = Uint8List(hash.process(b).lengthInBytes);
  for (int i = 0; i < hash.process(b).lengthInBytes; i++) sk[i] = hash.process(b)[i];
  return sk;
}
