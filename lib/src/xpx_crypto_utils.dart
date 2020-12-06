part of xpx_crypto;

const int IV_SIZE = 16;
const int KEY_SIZE = 32;

Uint8List bytesFromList(List<int> lst) => new Uint8List.fromList(lst);

int bytesToInteger(List<int> bytes) {
  num value = 0;
  // ignore: parameter_assignments
  bytes = bytes.sublist(0, 32);
  for (var i = 0; i < bytes.length; i++) {
    value += bytes[i] * pow(256, i);
  }
  return value.toInt();
}

var _byteMask = new BigInt.from(0xff);

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List encodeBigInt(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  final int size = (number.bitLength + 7) >> 3;
  final result = new Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    // ignore: parameter_assignments
    number = number >> 8;
  }
  return result;
}

Uint8List integerToBytes(int e, int length) {
  final byteList = new Uint8List(length);
  for (var i = 0; i < length; i++) {
    byteList[0 + i] = e >> (i * 8);
  }
  return byteList;
}

Uint8List addUint8List(Uint8List a, Uint8List b) {
  final Uint8List hash = Uint8List(b.length + a.length);
  for (int i = 0; i < a.length; i++) {
    hash[i] = a[i];
  }
  for (int i = 0; i < b.length; i++) {
    hash[i + a.length] = b[i];
  }
  return hash;
}

/// Creates random bytes with the given size.
Uint8List secureRandomBytes(int len) {
  return ed25519.SiriusNacl.randombytes(len);
}

/// Converts a hex string to a [Uint8List].
Uint8List hexToBytes(String hexString) {
  return Uint8List.fromList(hex.decode(hexString));
}

/// Converts a [Uint8List] to a hex string./
String bytesToHex(Uint8List bytes) {
  return hex.encode(bytes).toUpperCase();
}

/// Converts raw string into a string of single byte characters using UTF-8 encoding.
String _rawStringToUtf8(final String input) {
  final StringBuffer sb = new StringBuffer();
  for (int i = 0; i < input.length; i++) {
    final int cu = input.codeUnitAt(i);

    if (128 > cu) {
      sb.write(String.fromCharCode(cu));
    } else if ((127 < cu) && (2048 > cu)) {
      sb.write(String.fromCharCode((cu >> 6) | 192));
      sb.write(String.fromCharCode((cu & 63) | 128));
    } else {
      sb.write(String.fromCharCode((cu >> 12) | 224));
      sb.write(String.fromCharCode(((cu >> 6) & 63) | 128));
      sb.write(String.fromCharCode((cu & 63) | 128));
    }
  }

  return sb.toString();
}

/// Converts a UTF-8 [input] string to hex string.
String utf8ToHex(final String input) {
  final StringBuffer sb = new StringBuffer();
  final String rawString = _rawStringToUtf8(input);
  for (int i = 0; i < rawString.length; i++) {
    sb.write(rawString.codeUnitAt(i).toRadixString(16));
  }
  return sb.toString();
}

/// Converts [hex] string to a byte array.
///
/// Throws an exception upon failing.
List<int> getBytes(final String hex) {
  try {
    return _getBytesInternal(hex);
  } catch (e) {
    throw new ArgumentError(
        'Could not convert hex string into a byte array. Error: $e');
  }
}

/// Converts a hex string into byte array. Also tries to correct malformed hex string.
List<int> _getBytesInternal(final String hexString) {
  final String paddedHexString =
      0 == hexString.length % 2 ? hexString : '0$hexString';
  final List<int> encodedBytes = utf8ToByte(paddedHexString);
  return hex.decode(String.fromCharCodes(encodedBytes));
}

/// Converts a UTF-8 [input] string to an encoded byte array.
List<int> utf8ToByte(final String input) {
  return utf8.encode(input);
}

/// Converts an encoded byte array [input] to a UTF-8 string.
String byteToUtf8(final List<int> input) {
  return utf8.decode(input);
}

/// Converts byte array to a hex string.
///
/// Used for converting UTF-8 encoded data from and to bytes.
String getString(final List<int> bytes) {
  final String encodedString = hex.encode(bytes);
  return byteToUtf8(encodedString.codeUnits);
}

/// Encrypts a [message] with a shared key derived from [senderPrivateKey] and
/// [recipientPublicKey].
///
/// By default, the [message] is considered a UTF-8 plain text.
String encryptMessage(final String message, final String senderPrivateKey,
    final String recipientPublicKey,
    [final bool isHexMessage = false]) {
  ArgumentError.checkNotNull(message);
  ArgumentError.checkNotNull(senderPrivateKey);
  ArgumentError.checkNotNull(recipientPublicKey);

  String msg = isHexMessage ? message : utf8ToHex(message);

  final salt = secureRandomBytes(KEY_SIZE);

// Derive shared key
  final Uint8List senderByte = hexToBytes(senderPrivateKey);
  final Uint8List recipientByte = hexToBytes(recipientPublicKey);
  final Uint8List sharedKey = deriveSharedKey(senderByte, recipientByte, salt);

// Setup IV
  final IV iv = IV(secureRandomBytes(IV_SIZE));

// Setup AES cipher in CBC mode with PKCS7 padding
  final Encrypter encrypter =
      Encrypter(AES(Key(sharedKey), mode: AESMode.cbc, padding: 'PKCS7'));
  final Uint8List payload = hexToBytes(msg);
  final encryptedMessage = encrypter.algo.encrypt(payload, iv: iv);

// Creates a concatenated byte array as the encrypted payload
  final result = bytesToHex(salt) +
      bytesToHex(iv.bytes) +
      bytesToHex(encryptedMessage.bytes);

  return result;
}

/// Get a list of code unit of a hex string.
List<int> _getCodeUnits(final String hex) {
  final List<int> codeUnits = <int>[];
  for (int i = 0; i < hex.length; i += 2) {
    codeUnits.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }

  return codeUnits;
}

/// Tries to convert a [hex] string to a UTF-8 string.
/// When it fails to decode UTF-8, it returns the non UTF-8 string instead.
String tryHexToUtf8(final String hex) {
  final List<int> codeUnits = _getCodeUnits(hex);
  try {
    return byteToUtf8(codeUnits);
  } catch (e) {
    return String.fromCharCodes(codeUnits);
  }
}

/// Decrypts an [encryptedMessage] with a shared key derived from [recipientPrivateKey] and
/// [senderPublicKey].
///
/// Throws a [CryptoException] when decryption process fails.
/// By default, the [message] is considered a UTF-8 plain text.
String decryptMessage(final String encryptedMessage,
    final String recipientPrivateKey, final String senderPublicKey,
    [final bool isHexMessage = false]) {
  ArgumentError.checkNotNull(encryptedMessage);
  ArgumentError.checkNotNull(recipientPrivateKey);
  ArgumentError.checkNotNull(senderPublicKey);

  if (encryptedMessage.length < KEY_SIZE) {
    throw new ArgumentError('the encrypted payload has an incorrect size');
  }

  final Uint8List payloadBytes = getBytes(encryptedMessage);

  final Uint8List salt =
      Uint8List.fromList(payloadBytes.take(KEY_SIZE).toList());

  final Uint8List iv = Uint8List.fromList(
      payloadBytes.sublist(KEY_SIZE, KEY_SIZE + IV_SIZE).toList());

  final Uint8List encrypted =
      Uint8List.fromList(payloadBytes.skip(KEY_SIZE + IV_SIZE).toList());

  try {
// Derive shared key
    final Uint8List recipientByte = hexToBytes(recipientPrivateKey);
    final Uint8List senderByte = hexToBytes(senderPublicKey);
    final Uint8List sharedKey =
        deriveSharedKey(recipientByte, senderByte, salt);

    final Encrypter encrypter =
        Encrypter(AES(Key(sharedKey), mode: AESMode.cbc, padding: 'PKCS7'));

    final encryptedValue = Encrypted(encrypted);
    final ivValue = IV(iv);
    final decryptBytes = encrypter.decryptBytes(encryptedValue, iv: ivValue);
    final String decrypted = getString(decryptBytes);

// dev note: Use HexUtils for converting hex instead of using the hex converter from
// encrypt lib or any third party converter libs.
    final String result = isHexMessage ? decrypted : tryHexToUtf8(decrypted);

    return result;
  } catch (e) {
    throw new Exception('Failed to decrypt message');
  }
}

/// Derives a shared key using the [privateKey] and [publicKey].
Uint8List deriveSharedKey(final Uint8List privateKey, final Uint8List publicKey,
    final Uint8List salt) {
  final Uint8List sharedSecret =
      deriveSharedSecret(privateKey, publicKey, salt);
  final sha512digest = createSha3Digest(length: 32);
  final sharedKey = sha512digest.process(sharedSecret);
  return sharedKey;
}

Int64List gf([final Int64List init]) {
  return ed25519.SiriusNacl.gf(init);
}

void clamp(final Uint8List d) {
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
}

/// Creates a non-Keccak SHA3 256/512 digest based on the given bit [length].
///
/// Providing bit length 32 returns the non-Keccak SHA3-256.
/// Providing bit length 64 returns the non-Keccak SHA3-512. (Default return value)
SHA3Digest createSha3Digest({final int length = 64}) {
  if (length != 64 && length != 32) {
    throw ArgumentError(
        'Cannot create SHA3 hasher. Unexpected length: $length');
  }

  return 64 == length ? new SHA3Digest(512) : new SHA3Digest(256);
}

/// Computes the hash of a [secretKey] for scalar multiplication.
Uint8List prepareForScalarMult(final Uint8List secretKey) {
  final Uint8List hash = SHA3Digest(512).process(secretKey);
  final List<int> d = Uint8List.fromList(hash.buffer.asUint8List(0, 64));

  clamp(d);

  return d;
}

/// Derives a shared secret using the [privateKey] and [publicKey].
Uint8List deriveSharedSecret(final Uint8List privateKey,
    final Uint8List publicKey, final Uint8List salt) {
  if (KEY_SIZE != publicKey.length) {
    throw ArgumentError('Public key has unexpected size: ${publicKey.length}');
  }

  Uint8List d = prepareForScalarMult(privateKey);

// sharedKey = pack(p = d (derived from privateKey) * q (derived from publicKey))
  List<Int64List> q = [gf(), gf(), gf(), gf()];
  List<Int64List> p = [gf(), gf(), gf(), gf()];

// print(ByteUtils.bytesToHex(g.buffer.asUint8List()));

  Uint8List sharedSecret = Uint8List(KEY_SIZE);

  ed25519.SiriusNacl.unpack(q, publicKey);

  ed25519.SiriusNacl.scalarmult(p, q, d, 0);

  ed25519.SiriusNacl.pack(sharedSecret, p);
//print('sharedSecret01: $sharedSecret');
  print('\n');

  for (int i = 0; i < 32; i++) {
    sharedSecret[i] ^= salt[i];
  }
// print('sharedSecret02: $sharedSecret');

  return sharedSecret;
}
