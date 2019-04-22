part of nem2_crypto;

ECDomainParametersImpl constructFpStandardCurve(
    String name, Function constructor,
    {BigInt q, BigInt a, BigInt b, BigInt g, BigInt n, BigInt h, BigInt seed}) {
  var curve = new fp.ECCurve(q, a, b);
  var seedBytes = (seed == null) ? null : utils.encodeBigInt(seed);
  return constructor(
      name, curve, curve.decodePoint(utils.encodeBigInt(g)), n, h, seedBytes);
}