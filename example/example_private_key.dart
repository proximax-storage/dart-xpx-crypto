import "package:nem2_crypto/nem2_crypto.dart";

void main() {

  //  var sk = NewPrivateKeyFromHexString(
  //      "BB2B97D428832EFBA9816C62CC4911296EE3EE65DB19316D4AC1191028FE976C");
  //  var pk = NewPublicKeyFromHexString(
  //      "36C2E79313AD12BCD736CD272216F598EA12BF76E334156846B35268DE9077F6");
  //  var keyPair = NewKeyPair(sk, pk);
  String sk =
      "BB2B97D428832EFBA9816C62CC4911296EE3EE65DB19316D4AC1191028FE976C";
  var d = NewPrivateKeyFromHexString(sk);
  var keyPair = NewKeyPair(d, null);
  print(keyPair.toJson());
}
