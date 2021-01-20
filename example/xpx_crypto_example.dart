import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:xpx_crypto/xpx_crypto.dart';

void main() {
  /// New KeyPair from PrivateKey Hex String
  const String skHex = 'B38A1490B33A4BD718ABB0A1BEF389CAE07A435F3DEC39BC518D84B1ABF8531B';
  final KeyPair kp = KeyPair.fromHexString(skHex);

  print('privateKeyBytes: \"${kp.privateKey.raw}\"\n');
  print('publicKeyBytes: \"${kp.publicKey.raw}\"\n');
  print('publicKeyString: \"${hex.encode(kp.publicKey.raw)}\"\n');

  final Uint8List payload = utf8.encode('ProximaX Limited');

  final sing = kp.sign(payload);
  print(sing);

  final bool result = kp.verify(payload, sing);
  print('Verify: \"$result\"');
}
