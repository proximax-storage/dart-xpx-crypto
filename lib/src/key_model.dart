part of xpx_crypto;

class PrivateKey {
// I have kept this field for compatibility
  Uint8List Raw = Uint8List(64);

  // NewPrivateKey creates a new private key from []byte
  PrivateKey([Uint8List raw]){
    Raw = raw == null ? Uint8List(64) : Uint8List.fromList(raw.toList());
  }

  // NewPrivateKeyfromHexString creates a private key from a hex strings.
  PrivateKey.fromHexString(String sHex) {
    var raw = HexDecodeStringOdd(sHex);
    Raw = Uint8List.fromList(raw.toList());
  }

  // NewPrivateKeyFromBigInt creates a new private key from BigInt
  PrivateKey.fromBigInt(BigInt val) {
    Raw = encodeBigInt(val);
  }

  @override
  String toString() => HEX.encode(Raw.toList()).toUpperCase();
}

class PublicKey {
// I have kept this field for compatibility
  Uint8List Raw = Uint8List(32);

  PublicKey();

  @override
  String toString() => HEX.encode(Raw.toList()).toUpperCase();
}

// NewPrivateKey creates a new private key from []byte
PublicKey NewPublicKey(Uint8List raw) {
  var sk = new PublicKey();
  sk.Raw = Uint8List.fromList(raw.toList());
  return sk;
}

// NewPrivateKeyfromHexString creates a private key from a hex strings.
PublicKey NewPublicKeyFromHexString(String sHex) {
  var raw = HEX.decode(sHex);
  return NewPublicKey(raw);
}

// NewPrivateKeyFromBigInt creates a new private key from BigInt
PublicKey NewPublicKeyFromBigInt(BigInt val) {
  var sk = new PublicKey();
  sk.Raw = encodeBigInt(val);
  return sk;
}

// HexDecodeStringOdd return padding hex representation of string
Uint8List HexDecodeStringOdd(String s) {
  if (s.length % 2 != 0) {
    s = "0" + s;
  }
  return HEX.decode(s);
}
