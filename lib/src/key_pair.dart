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

  /*
   *   Signs the message using the secret key and returns a signature.
   * */
  Uint8List sign(Uint8List message) {
    Uint8List to = addUint8List(_privateKey.Raw, _publicKey.Raw);
    var key = ed25519.Signature(null, to);
    Uint8List signedMsg = key.sign(message);
    Uint8List sig = Uint8List(nem2Const.signatureLength);
    for (int i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
    return sig;
  }

  /*
   *   Verifies the signature for the message and
   *   returns true if verification succeeded or false if it failed.
   * */
  bool verify(Uint8List message, Uint8List signature) {
    if (signature.length != nem2Const.signatureLength) return false;
    if (_publicKey.Raw.length != nem2Const.publicKeyLength) return false;
    Uint8List sm = Uint8List(nem2Const.signatureLength + message.length);
    Uint8List m = Uint8List(nem2Const.signatureLength + message.length);
    for (int i = 0; i < nem2Const.signatureLength; i++) sm[i] = signature[i];
    for (int i = 0; i < message.length; i++)
      sm[i + nem2Const.signatureLength] = message[i];
    return (ed25519.CatapultNacl.crypto_sign_open(
        m, -1, sm, 0, sm.length, _publicKey.Raw) >=
        0);
  }

  @override
  String toString() =>
      'KeyPair[PrivateKey=$_privateKey, PublicKey=$_publicKey]';

  Map<String, dynamic> toJson() {
    return {'privateKey': _privateKey, 'publicKey': _publicKey};
  }
}

//NewKeyPair The public key is calculated from the private key.
KeyPair NewKeyPair(PrivateKey privateKey, PublicKey publicKey) {
  KeyPair kp = new KeyPair();

  if (publicKey == null) {
    kp = ed25519.Signature.keyPair_fromSeed(privateKey.Raw);

    Uint8List sk = Uint8List(nem2Const.privateKeyLen);
    for (int i = 0; i < sk.length; i++) sk[i] = kp.privateKey.Raw[i];
    kp.privateKey.Raw = sk;
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

Uint8List addUint8List(Uint8List a, Uint8List b) {
  Uint8List hash = Uint8List(b.length + a.length);
  for (int i = 0; i < a.length; i++) hash[i] = a[i];
  for (int i = 0; i < b.length; i++) hash[i + a.length] = b[i];
  return hash;
}