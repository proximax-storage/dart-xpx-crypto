part of nem2_crypto;

// KeyPair represent the pair of keys - private & public
class KeyPair {
  PrivateKey _privateKey = null;
  PublicKey _publicKey = null;

  KeyPair() {
    _privateKey = PrivateKey();
    _publicKey = PublicKey();
  }

  PublicKey get publicKey => _publicKey;

  PrivateKey get privateKey => _privateKey;

  @override
  String toString() =>
      'KeyPair[PrivateKey=$_privateKey, PublicKey=$_publicKey]';
}

//NewKeyPair The public key is calculated from the private key.
KeyPair NewKeyPair(PrivateKey privateKey, PublicKey publicKey) {
  KeyPair kp = new KeyPair();

  if (publicKey == null) {
    var raw = ed25519.Signature.keyPair_fromSeed(privateKey.Raw);
    Uint8List sk = Uint8List(nem2Const.privateKeyLen);
    for (int i = 0; i < sk.lengthInBytes; i++) sk[i] = raw.secretKey[i];
    kp.privateKey.Raw = sk;
    kp.publicKey.Raw = raw.publicKey;
  } else {
    kp.publicKey.Raw = publicKey.Raw;
    kp.privateKey.Raw = privateKey.Raw;
  }
  return kp;
}

//NewRandomKeyPair creates a random key pair.
KeyPair NewRandomKeyPair() {
  var randGen = new Random.secure();
  var seed = new List<int>.generate(
      64, (_) => randGen.nextInt(nem2Const.bits));
  return NewKeyPair(NewPrivateKey(Uint8List.fromList(seed.toList())), null);
}
