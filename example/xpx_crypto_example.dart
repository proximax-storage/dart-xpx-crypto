import "dart:convert";
import 'dart:typed_data';
import 'package:hex/hex.dart';
import "package:xpx_crypto/xpx_crypto.dart";

void main() {
  /// New KeyPair from PrivateKey Hex String
  String skHex =
      "BB2B97D428832EFBA9816C62CC4911296EE3EE65DB19316D4AC1191028FE976C";
  KeyPair kp = new KeyPair.fromHexString(skHex);

  print("privateKey: \"${kp.privateKey}\"\n");
  print("publicKey: \"${kp.publicKey}\"\n");

  Uint8List msg = utf8.encode("Proximax is awesome !");

  var sing = kp.sign(msg);
  print("Signature: \"${HEX.encode(sing).toUpperCase()}\"\n");

  bool result = kp.verify(msg, sing);
  print("Verify: \"${result}\"");
}
