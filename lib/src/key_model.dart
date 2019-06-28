part of xpx_crypto;

class PrivateKey {
  // NewPrivateKey creates a new private key from []byte
  PrivateKey([Uint8List raw]) {
    this.raw = raw == null ? Uint8List(64) : Uint8List.fromList(raw.toList());
  }

  // NewPrivateKeyfromHexString creates a private key from a hex strings.
  PrivateKey.fromHexString(String sHex) {
    var raw = hexDecodeStringOdd(sHex);
    raw = Uint8List.fromList(raw.toList());
  }

  // NewPrivateKeyFromBigInt creates a new private key from BigInt
  PrivateKey.fromBigInt(BigInt val) {
    raw = encodeBigInt(val);
  }

  // I have kept this field for compatibility
  Uint8List raw = Uint8List(64);

  @override
  String toString() => hex.encode(raw.toList()).toUpperCase();
}

class PublicKey {
  PublicKey();
  // NewPrivateKey creates a new private key from []byte
  PublicKey.fromList(Uint8List raw) {
    raw = Uint8List.fromList(raw.toList());
  }

  // NewPrivateKeyFromHexString creates a private key from a hex strings.
  PublicKey.fromhexString(String sHex) {
    raw = hex.decode(sHex);
  }

  // NewPrivateKeyFromBigInt creates a new private key from BigInt
  PublicKey.fromBigInt(BigInt val) {
    raw = encodeBigInt(val);
  }

  // I have kept this field for compatibility
  Uint8List raw = Uint8List(32);

  @override
  String toString() => hex.encode(raw.toList()).toUpperCase();
}

// hexDecodeStringOdd return padding hex representation of string
Uint8List hexDecodeStringOdd(String s) {
  if (s.length % 2 != 0) {
    // ignore: parameter_assignments
    s = '0' + s;
  }
  return hex.decode(s);
}
