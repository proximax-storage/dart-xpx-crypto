import 'dart:convert';
import 'dart:typed_data';
import 'package:xpx_crypto/xpx_crypto.dart';
import 'package:convert/convert.dart';

void main() {
  /// New KeyPair from PrivateKey Hex String
  const String skHex =
      '68f50e10e5b8be2b7e9ddb687a667d6e94dd55fe02b4aed8195f51f9a242558b';
  final KeyPair kp = new KeyPair.fromHexString(skHex);

  print('privateKey: \"${kp.privateKey}\"\n');
  print('publicKey: \"${kp.publicKey}\"\n');

  final Uint8List payload = utf8.encode('ProximaX Limited');

  final sing = kp.sign(payload);
  print('Signature: \"${hex.encode(sing).toUpperCase()}\"\n');

  final bool result = kp.verify(payload, sing);
  print('Verify: \"$result\"');
}
