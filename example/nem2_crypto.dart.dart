import "dart:convert";
import 'dart:typed_data';
import 'package:hex/hex.dart';
import "package:xpx_crypto/xpx_crypto.dart";

void main() {
  String sk =
      "BB2B97D428832EFBA9816C62CC4911296EE3EE65DB19316D4AC1191028FE976C";
  var d = NewPrivateKeyFromHexString(sk);
  var keyPair = NewKeyPair(d, null);

  print("${keyPair.toString()}\n");

  Uint8List msg = utf8.encode("NEM is awesome !");

  var sing = keyPair.sign(msg);
  print("Signature: \"${HEX.encode(sing).toUpperCase()}\"\n");

  bool result = keyPair.verify(msg,  sing);
  print("Verify: \"${result}\"");

}
