part of xpx_crypto;

// KeyPair represent the pair of keys - private & public
class KeyPair {
  KeyPair() {
    _privateKey = PrivateKey();
    _publicKey = PublicKey();
  }

  /// NewKeyPair The public key is calculated from the private key.
  KeyPair.fromPrivateKey(PrivateKey privateKey) {
    final pk = ed25519.Signature.keyPair_fromSeed(privateKey.raw);
    final sk = PrivateKey(Uint8List.fromList(pk._privateKey.raw.getRange(0, 32).toList()));
    _privateKey = sk;
    _publicKey = pk._publicKey;
  }

  KeyPair.fromHexString(String sHex) {
    final sHexRaw = hexDecodeStringOdd(sHex);
    final pk = ed25519.Signature.keyPair_fromSeed(sHexRaw);

    final sk = PrivateKey(Uint8List.fromList(pk.privateKey.raw.getRange(0, 32).toList()));
    _privateKey = sk;
    _publicKey = pk.publicKey;
  }

  /// NewRandomKeyPair creates a random key pair.
  KeyPair.fromRandomKeyPair() {
    final randGen = Random.secure();
    final seed = new List<int>.generate(64, (_) => randGen.nextInt(XpxConst.bits));
    final kp = KeyPair.fromPrivateKey(new PrivateKey(Uint8List.fromList(seed.toList())));
    _privateKey = kp._privateKey;
    _publicKey = kp._publicKey;
  }

  PrivateKey _privateKey;
  PublicKey _publicKey;

  PublicKey get publicKey => _publicKey;

  PrivateKey get privateKey => _privateKey;

  Uint8List sign(Uint8List message) {
    final Uint8List to = addUint8List(_privateKey.raw, _publicKey.raw);
    final key = ed25519.Signature(null, to);
    final Uint8List signedMsg = key.sign(message);
    final Uint8List sig = Uint8List(XpxConst.signatureLength);
    for (int i = 0; i < sig.length; i++) {
      sig[i] = signedMsg[i];
    }
    return sig;
  }

  bool verify(Uint8List message, Uint8List signature) {
    if (signature.length != XpxConst.signatureLength) return false;
    if (_publicKey.raw.length != XpxConst.publicKeyLength) return false;
    final Uint8List sm = Uint8List(XpxConst.signatureLength + message.length);
    final Uint8List m = Uint8List(XpxConst.signatureLength + message.length);
    for (int i = 0; i < XpxConst.signatureLength; i++) {
      sm[i] = signature[i];
    }
    for (int i = 0; i < message.length; i++) {
      sm[i + XpxConst.signatureLength] = message[i];
    }
    return ed25519.SiriusNacl.crypto_sign_open(m, -1, sm, 0, sm.length, _publicKey.raw) >= 0;
  }

  @override
  String toString() => '{\n'
      '\tprivateKey: $_privateKey,\n'
      '\tpublicKey: $_publicKey\n'
      '}\n';

  Map<String, dynamic> toJson() => {'privateKey': _privateKey, 'publicKey': _publicKey};
}
