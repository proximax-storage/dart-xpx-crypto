part of xpx_crypto;

// ignore: avoid_classes_with_only_static_members
/// Package wide constants
class XpxConst {
  /// Result key
  static const String nem2ResultKey = 'result';

  /// Error key
  static const String nem2ErrorKey = 'error';

  /// The leading hex indicator
  static const String leadingHexString = '0x';

  static const int bits = 256;

  /// Address character length
  static const int addressLen = 40;

  /// PubicKey character length
  static const int publicKeyLen = 32;

  /// Length of signing public key in bytes.
  static const int publicKeyLength = 32;

  /// Private character length
  static const int privateKeyLen = 32;

  /// Length of signing secret key in bytes.
  static const int privateKeyLength = 64;

  /// Length of seed for nacl.sign.keyPair.fromSeed in bytes.
  static const int seedLength = 32;

  /// Length of signature in bytes.
  static const int signatureLength = 64;
}
