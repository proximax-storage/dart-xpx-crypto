part of nem2_crypto;


Uint8List bytesFromList(List<int> lst) => new Uint8List.fromList(lst);

int bytesToInteger(List<int> bytes) {
  num value = 0;
  bytes = bytes.sublist(0, 32);
  for (var i = 0; i < bytes.length; i++) {
    value += bytes[i] * pow(256, i);
  }
  ;
  return value.toInt();
}

Uint8List encodePoint(List<BigInt> P) {
  var x = P[0];
  var y = P[1];
  var encoded = utils.encodeBigInt(y + ((x & BigInt.one) << 255));
  return encoded;
}

Uint8List integerToBytes(int e, int length) {
  var byteList = new Uint8List(length);
  for (var i = 0; i < length; i++) {
    byteList[0 + i] = (e >> (i * 8));
  }
  ;
  return byteList;
}

List<BigInt> scalarMult(List<BigInt> P, BigInt e) {
  if (e == BigInt.zero) {
    return [BigInt.zero, BigInt.one];
  }
   List<BigInt> Q;
  try {
    Q = scalarMult(P, e ~/ BigInt.two);
  } catch (error) {
    print('Error occured during division:${error}');
  }

  Q = edwards(Q, Q);
  if (e & BigInt.one > BigInt.zero ) {
    Q = edwards(Q, P);
  };

   return Q;
}

List<BigInt> edwards(List<BigInt> P, List<BigInt> Q) {
  BigInt x1, y1, x2, y2, x3, y3;
  x1 = P[0];
  y1 = P[1];
  x2 = Q[0];
  y2 = Q[1];
  x3 = (x1 * y2 + x2 * y1) * modularInverse(BigInt.one + d * x1 * x2 * y1 * y2);
  y3 = (y1 * y2 + x1 * x2) * modularInverse(BigInt.one - d * x1 * x2 * y1 * y2);
  return [x3 % primeQ, y3 % primeQ];
}

BigInt modularInverse(BigInt z) => z.modInverse(primeQ);