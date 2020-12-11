import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:xpx_crypto/xpx_crypto.dart';

void main() {
  /// New KeyPair from PrivateKey Hex String
  const String skHex =
      'B38A1490B33A4BD718ABB0A1BEF389CAE07A435F3DEC39BC518D84B1ABF8531B';
  final KeyPair kp = new KeyPair.fromHexString(skHex);

  print('privateKey: \"${kp.privateKey.raw}\"\n');
  print('publicKey: \"${kp.publicKey.raw}\"\n');
  print('publicKey: \"${hex.encode(kp.publicKey.raw)}\"\n');

  final Uint8List payload = utf8.encode('ProximaX Limited');

//  print(payload);

  final sing = kp.sign(payload);
  print(sing);
//  print('Signature: \"${hex.encode(sing).toUpperCase()}\"\n');

  final bool result = kp.verify(payload, sing);
  print('Verify: \"$result\"');
}
