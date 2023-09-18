import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart' show hexToBytes, fillBytesWithSecureRandom;

import 'ed25519.dart';

/// Encrypts a [message] with a shared key derived from [senderPrivateKey] and
/// [recipientPublicKey].
///
/// By default, the [message] is considered a UTF-8 plain text.
Future<List<int>> encryptMessage(
    final String message, final List<int> senderPrivateKey, final List<int> recipientPublicKey,
    [final bool isHexMessage = false]) async {
  ArgumentError.checkNotNull(message);
  ArgumentError.checkNotNull(senderPrivateKey);
  ArgumentError.checkNotNull(recipientPublicKey);

  final msg = isHexMessage ? hexToBytes(message) : utf8.encode(message);

  final salt = Uint8List(32);
  fillBytesWithSecureRandom(salt);

  final publicKey = SimplePublicKey(recipientPublicKey, type: KeyPairType.ed25519);
  final secretKey = await SiriusEd25519().newKeyPairFromSeed(senderPrivateKey);

  final _sharedSecret =
      SiriusEd25519.sharedSecretSync(keyPairData: await secretKey.extract(), remotePublicKey: publicKey, salt: salt);

  final cipher = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);

  final secretBox = await cipher.encrypt(msg, secretKey: _sharedSecret);

  final result = <int>[];
  result.addAll(salt);
  result.addAll(secretBox.concatenation(mac: false));
  return result;
}

/// Decrypts an [encryptedMessage] with a shared key derived from [recipientPrivateKey] and
/// [senderPublicKey].
///
/// Throws a [CryptoException] when decryption process fails.
/// By default, the [message] is considered a UTF-8 plain text.
Future<List<int>> decryptMessage(
    final Uint8List encryptedMessage, final List<int> recipientPrivateKey, final List<int> senderPublicKey) async {
  ArgumentError.checkNotNull(encryptedMessage);
  ArgumentError.checkNotNull(recipientPrivateKey);
  ArgumentError.checkNotNull(senderPublicKey);

  if (encryptedMessage.length < 32) {
    throw ArgumentError('the encrypted payload has an incorrect size');
  }

  final salt = List<int>.unmodifiable(Uint8List.view(
    encryptedMessage.buffer,
    encryptedMessage.offsetInBytes,
    32,
  ));

  final nonce = List<int>.unmodifiable(Uint8List.sublistView(
    encryptedMessage,
    salt.length,
    salt.length + 16,
  ));

  final cipherText = List<int>.unmodifiable(Uint8List.view(
    encryptedMessage.buffer,
    encryptedMessage.offsetInBytes + salt.length + nonce.length,
    encryptedMessage.length - salt.length - nonce.length,
  ));

  final secretKey = await SiriusEd25519().newKeyPairFromSeed(recipientPrivateKey);
  final publicKey = SimplePublicKey(senderPublicKey, type: KeyPairType.ed25519);

  final _secretKey =
      SiriusEd25519.sharedSecretSync(keyPairData: await secretKey.extract(), remotePublicKey: publicKey, salt: salt);

  final cipher = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);

  final _secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac.empty);
  final decrypt = await cipher.decrypt(
    _secretBox,
    secretKey: _secretKey,
  );

  return decrypt;
}
