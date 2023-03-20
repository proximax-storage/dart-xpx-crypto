import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Signature, SimplePublicKey;
import 'package:cryptography/src/utils.dart'
    show hexToBytes, hexFromBytes, fillBytesWithSecureRandom, constantTimeBytesEquality;
import 'package:quiver/core.dart';

import 'ed25519.dart';

class KeyPair {
  static final _algorithm = SiriusEd25519();
  late Uint8List publicKey;
  late Uint8List secretKey;

  // private constructor
  KeyPair._(this.secretKey, this.publicKey);

  // A private method that creates a new instance of [KeyPair].
  // Throws an error when [privateKey] has an unexpected length.
  static KeyPair _create(Uint8List privateKey, Uint8List publicKey) {
    ArgumentError.checkNotNull(privateKey);
    ArgumentError.checkNotNull(publicKey);
    if (privateKey.lengthInBytes != 32) {
      throw ArgumentError('Invalid length for privateKey. Length: ${privateKey.lengthInBytes}');
    }
    return KeyPair._(privateKey, publicKey);
  }

  /// Creates a key pair from a [hexEncodedPrivateKey].
  /// The public key is extracted from the private key.
  ///
  /// Throws a [CryptoException] when the private key has an invalid length.
  static Future<KeyPair> fromPrivateKey(final String hexEncodedPrivateKey) async {
    final privateKeySeed = hexToBytes(hexEncodedPrivateKey);
    if (32 != privateKeySeed.length) {
      throw ArgumentError('Private key has an unexpected size. '
          'Expected: 32, Got: ${privateKeySeed.length}');
    }

    final publicKey = await extractPublicKey(privateKeySeed);
    return _create(Uint8List.fromList(privateKeySeed), publicKey);
  }

  /// Creates a random key pair based on the given [hashSize] (optional).
  /// By default, the [hashSize] is set to 32-bytes.
  static Future<KeyPair> random() async {
    return KeyPair.fromPrivateKey(hexFromBytes(randomKey()));
  }

  /// Extract a public key byte from a [privateKeySeed].
  static Future<Uint8List> extractPublicKey(final List<int> privateKeySeed) async {
    if (privateKeySeed.isEmpty) {
      return throw ArgumentError('Must not be empty');
    }
    final _keyPair = await _algorithm.newKeyPairFromSeed(privateKeySeed);
    return Uint8List.fromList((await _keyPair.extractPublicKey()).bytes);
  }

  /// Creates a random public key.
  static Uint8List randomKey() {
    var bytes = Uint8List(32);
    fillBytesWithSecureRandom(bytes);
    return bytes;
  }

  /// Signs the [data].
  Future<Signature> sign(final Uint8List data) async {
    final keyPair = await _algorithm.newKeyPairFromSeed(secretKey.toList());
    return KeyPair._algorithm.sign(data, keyPair: keyPair);
  }

  /// Verifies that the [signature] is signed using the [publicKey] and the [data].
  static Future<bool> verify(
      {required Uint8List publicKey, required Uint8List data, required Signature signature}) async {
    final signaturePublicKeyBytes = (signature.publicKey as SimplePublicKey).bytes;
    if (!constantTimeBytesEquality.equals(publicKey.toList(), signaturePublicKeyBytes)) return false;
    return _algorithm.verify(data, signature: signature);
  }

  @override
  bool operator ==(final other) =>
      identical(this, other) ||
      other is KeyPair &&
          runtimeType == other.runtimeType &&
          listsEqual(secretKey, other.secretKey) &&
          listsEqual(publicKey, other.publicKey);

  @override
  int get hashCode => hash2(secretKey.hashCode, publicKey.hashCode);
}

bool listsEqual(List? a, List? b) {
  if (a == b) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;

  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }

  return true;
}
