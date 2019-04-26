part of nem2_crypto;

// HashesSha3_256 return sha3 256 hash of byte
Uint8List HashesSha3_256(Uint8List b){
  var hash = new Digest("SHA-3/256");
  return hash.process(b);
}

// HashesRipemd160 return ripemd160 hash of byte
Uint8List HashesRipemd160(Uint8List b){
  var hash = new Digest("RIPEMD-160");
  Uint8List sk = Uint8List(hash.process(b).lengthInBytes);
    for (int i = 0; i < hash.process(b).lengthInBytes; i++) sk[i] = hash.process(b)[i];
  return sk;
}