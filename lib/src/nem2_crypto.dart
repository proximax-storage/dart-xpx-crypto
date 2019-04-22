part of nem2_crypto;

class KeyPair {
  Uint8List privateKey;
  Uint8List publicKey;
  KeyPair({this.privateKey, this.publicKey});
}

KeyPair KeyPairCreate(String pk) {
  var kp = new KeyPair();
  if (pk != "") {
    if (pk.length != nem2Const.privateKeyLen) {

      throw ArgumentError.notNull(
          'insufficient seed length, should be 64, but got' +
              pk.length.toString());
    }

    kp.privateKey = new Uint8List.fromList(HEX.decode(pk));
    kp.publicKey = new Uint8List(nem2Const.publicKeyLen);

  } else {
    var randGen = new Random.secure();
    kp.privateKey = bytesFromList(new List<int>.generate(nem2Const.privateKeyLen, (_) => randGen.nextInt(nem2Const.bits)));
    kp.publicKey = new Uint8List(nem2Const.publicKeyLen);
  }
  var digest = Hash(bytesFromList(kp.privateKey.getRange(0, 32).toList()));

  var clamped = bitClamp(digest);

  kp.publicKey = _publicKey(clamped);

  return kp;
}

Uint8List _publicKey(Uint8List sk) {
  var clamped = utils.decodeBigInt(sk.getRange(0, 32).toList());
  var encoded = encodePoint(scalarMult(basePoint, clamped));
  return encoded;
}

Uint8List Hash(Uint8List m) {
  return new Digest('SHA-512').process(m);
}

Uint8List bitClamp(Uint8List bytes) {
  bytes[0] &= 248;
  bytes[31] &= 63;
  bytes[31] |= 64;
  return bytes;
}

BigInt readBytes(Uint8List bytes) {
  BigInt read(int start, int end) {
    if (end - start <= 4) {
      int result = 0;
      for (int i = end - 1; i >= start; i--) {
        result = result * 256 + bytes[i];
      }
      return new BigInt.from(result);
    }
    int mid = start + ((end - start) >> 1);
    var result = read(start, mid) + read(mid, end) * (BigInt.one << ((mid - start) * 8));
    return result;
  }
  return read(0, bytes.length);
}

BigInt bytesToBigInt(List s) {
    if (s == null || s.length == 0) {
      return BigInt.zero;
    }

    int v = 0;
    for (int byte in s) {
      v = (v << 8) | (byte & 0xFF);
    }

    return BigInt.from(v);
}