part of nem2_crypto;

/// Package wide constants
class nem2Const {
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

  /// Private character length
  static const int privateKeyLen = 32;
}
