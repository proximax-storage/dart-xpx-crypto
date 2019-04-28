//import "package:nem2_crypto/nem2_crypto.dart";
//
//void main() {
//  var pk = NewPublicKeyFromHexString(
//      "1288C721FE54DF531DE53120612E76B127DD2C4C5E3E4AB6B90A4C1FEEAF1B75");
//  var sk = NewPrivateKeyFromHexString(
//      "0DA6F90F86835F4822D1C721DAF52C5E47AE1AD488D1733D42464CCC090413FC");
//  var keyPair = NewKeyPair(sk, null);
//  print(keyPair);
//}

import "package:nem2_crypto/nem2_crypto.dart";

void main() {
  String sk = "BB2B97D428832EFBA9816C62CC4911296EE3EE65DB19316D4AC1191028FE976C";
  var d =  NewPrivateKeyFromHexString(sk);
  var kp = NewKeyPair(d, null);
  print(kp.toJson());
}