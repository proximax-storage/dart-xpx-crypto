// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart'
    show
        Ed25519,
        KeyPairType,
        SimpleKeyPair,
        PublicKey,
        Signature,
        SimplePublicKey,
        KeyPair,
        SimpleKeyPairData;
import 'package:cryptography/src/cryptography/key_pair.dart';
import 'package:cryptography/src/cryptography/secret_key.dart';
import 'package:cryptography/src/dart/ed25519_impl.dart';
import 'package:cryptography/src/utils.dart'
    show bigIntFromBytes, fillBytesWithSecureRandom;
import 'package:sha3/sha3.dart';

/// [Ed25519] signature algorithm implemented in pure Dart.
class SiriusEd25519 extends Ed25519 {
  SiriusEd25519() : super.constructor();

  @override
  KeyPairType get keyPairType => KeyPairType.ed25519;

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed must have 32 bytes');
    }
    return Future<SimpleKeyPairData>.value(SimpleKeyPairData(
      List<int>.unmodifiable(seed),
      type: KeyPairType.ed25519,
      publicKey: _publicKey(seed),
    ));
  }

  // Compresses a point
  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
    PublicKey? publicKey,
  }) async {
    var sha3_512 = SHA3(512, SHA3_PADDING, 512);
    final keyPairData = (await keyPair.extract()) as SimpleKeyPairData;
    final privateKeyBytes = keyPairData.bytes;

    // Take SHA3_512 hash of the private key.
    final privateKeyHash = sha3_512.update(privateKeyBytes).digest();
    final privateKeyHashFixed = privateKeyHash.sublist(0, 32);
    _setPrivateKeyFixedBits(privateKeyHashFixed);

    // We get public key by multiplying the modified private key hash with G.
    final publicKeyBytes = _pointCompress(_pointMul(
      Register25519()..setBytes(Uint8List.fromList(privateKeyHashFixed)),
      Ed25519Point.base,
    ));

    final publicKey = SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.ed25519,
    );

    // Calculate hash of the input.
    // The second half of the seed hash is used as the salt.
    sha3_512 = SHA3(512, SHA3_PADDING, 512);
    final mhSalt = privateKeyHash.sublist(32);
    final mhBytes = _join([mhSalt, message]);
    final mh = sha3_512.update(mhBytes).digest();
    final mhL = RegisterL()..readBytes(mh);

    // Calculate point R.
    final pointR = _pointMul(mhL.toRegister25519(), Ed25519Point.base);
    final pointRCompressed = _pointCompress(pointR);

    // Calculate s
    final shBytes = _join([
      pointRCompressed,
      publicKey.bytes,
      message,
    ]);
    sha3_512 = SHA3(512, SHA3_PADDING, 512);
    final sh = sha3_512.update(shBytes).digest();
    final s = RegisterL()..readBytes(sh);
    s.mul(s, RegisterL()..readBytes(privateKeyHashFixed));
    s.add(s, mhL);
    final sBytes = s.toBytes();

    // The signature bytes are ready
    final result = Uint8List.fromList(<int>[
      ...pointRCompressed,
      ...sBytes,
    ]);

    return Signature(
      result,
      publicKey: publicKey,
    );
  }

  @override
  Future<bool> verify(List<int> input, {required Signature signature}) async {
    // Check that parameters appear valid
    final publicKeyBytes = (signature.publicKey as SimplePublicKey).bytes;
    final signatureBytes = signature.bytes;
    if (publicKeyBytes.length != 32) {
      throw ArgumentError.value(
        signature,
        'signature',
        'Invalid public key length',
      );
    }
    if (signatureBytes.length != 64) {
      throw ArgumentError.value(
        signature,
        'signature',
        'Invalid signature length',
      );
    }

    // Decompress `a`
    final a = _pointDecompress(publicKeyBytes);
    if (a == null) {
      return false;
    }

    // Decompress `r`
    final rBytes = signatureBytes.sublist(0, 32);
    final r = _pointDecompress(rBytes);
    if (r == null) {
      return false;
    }

    // Get `s`
    final s = bigIntFromBytes(signatureBytes.sublist(32));
    if (s >= RegisterL.constantL) {
      return false;
    }

    // Calculate `h`
    final sha3_512 = SHA3(512, SHA3_PADDING, 512);
    final hh = sha3_512.update(_join([rBytes, publicKeyBytes, input]));
    final h = RegisterL();
    h.readBytes(hh.digest());

    // Calculate: s * basePoint
    final sB = _pointMul(Register25519()..setBigInt(s), Ed25519Point.base);

    // Calculate: h * a + r
    final rhA = Ed25519Point.zero();
    _pointAdd(
      rhA,
      _pointMul(h.toRegister25519(), a),
      r,
    );

    // Compare
    return sB.equals(rhA);
  }

  SimplePublicKey _publicKey(List<int> seed) {
    // Take SHA3_512 hash of the private key.
    final sha3_512 = SHA3(512, SHA3_PADDING, 512);
    final hashOfPrivateKey = sha3_512.update(seed).digest();
    final tmp = Uint8List.fromList(hashOfPrivateKey.sublist(0, 32));
    SiriusEd25519._setPrivateKeyFixedBits(tmp);

    // We get public key by multiplying the modified private key hash with G.
    final publicKeyBytes = SiriusEd25519._pointCompress(SiriusEd25519._pointMul(
      Register25519()..setBytes(tmp),
      Ed25519Point.base,
    ));

    return SimplePublicKey(
      List<int>.unmodifiable(publicKeyBytes),
      type: KeyPairType.ed25519,
    );
  }

  static Uint8List _join(List<List<int>> parts) {
    final totalLength = parts.fold<int>(0, (a, b) => a + b.length);
    final buffer = Uint8List(totalLength);
    var i = 0;
    for (var part in parts) {
      buffer.setAll(i, part);
      i += part.length;
    }
    return buffer;
  }

  static void _pointAdd(
    Ed25519Point r,
    Ed25519Point p,
    Ed25519Point q, {
    Ed25519Point? tmp,
  }) {
    tmp ??= Ed25519Point.zero();

    final a = r.x;
    final b = r.y;
    final c = r.z;
    final d = r.w;

    final e = tmp.x;
    final f = tmp.y;
    final g = tmp.z;
    final h = tmp.w;

    // a = (p.y - p.x) * (q.y - q.x)
    // b = (p.y + p.x) * (q.y + q.x)
    // c = 2 * p.w * q.w * D
    // d = 2 * p.z * q.z

    a.sub(p.y, p.x);
    b.sub(q.y, q.x);
    a.mul(a, b);

    b.add(p.y, p.x);
    c.add(q.y, q.x);
    b.mul(b, c);

    c.mul(Register25519.two, p.w);
    c.mul(c, q.w);
    c.mul(c, Register25519.D);

    d.mul(Register25519.two, p.z);
    d.mul(d, q.z);

    // e = b - a
    // f = d - c
    // g = d + c
    // h = b + a

    e.sub(b, a);
    f.sub(d, c);
    g.add(d, c);
    h.add(b, a);

    // a = e * f
    // b = g * h
    // c = f * g
    // d = e * h

    a.mul(e, f);
    b.mul(g, h);
    c.mul(f, g);
    d.mul(e, h);

    // [a, b, c, d] are output registers
  }

  static List<int> _pointCompress(Ed25519Point p) {
    final zInv = Register25519();
    final x = Register25519();
    final y = Register25519();

    // zInv = p.z ^ (P - 2) mod (2^255 - 19)
    zInv.pow(p.z, Register25519.PMinusTwo);

    // x = p.x * zInv mod (2^255 - 19)
    x.mul(p.x, zInv);

    // y = p.y * zInv mod (2^255 - 19)
    y.mul(p.y, zInv);

    // Highest bit of y = lowest bit of x
    assert(0x8000 & y.data[15] == 0);
    y.data[15] |= (0x1 & x.data[0]) << 15;

    return y.toBytes(Uint8List(32));
  }

  static Ed25519Point? _pointDecompress(List<int> pointBytes) {
    assert(pointBytes.length == 32);
    final s = Uint8List.fromList(pointBytes);
    final sign = (0x80 & s[31]) >> 7;
    s[31] &= 0x7F;

    final y = Register25519();
    y.setBytes(s);

    if (y.isGreaterOrEqual(Register25519.P)) {
      // Got invalid Y
      return null;
    }

    // Temporary arrays
    final v0 = Register25519();
    final v1 = Register25519();

    // (y * y - 1)
    v0.mul(y, y);
    v0.sub(v0, Register25519.one);

    // (y * y * D + 1)
    v1.mul(y, y);
    v1.mul(v1, Register25519.D);
    v1.add(v1, Register25519.one);
    v1.pow(v1, Register25519.PMinusTwo);

    // x2 = (y * y - 1) * (_constantD * y * y + 1)^(P-2) % P
    final x2 = Register25519();
    x2.mul(v0, v1);

    if (x2.isZero) {
      if (sign == 1) {
        // Got invalid Y
        return null;
      } else {
        // A special case
        return Ed25519Point(
          Register25519.zero,
          y,
          Register25519.one,
          Register25519.zero,
        );
      }
    }

    // x = x2^((P + 3) ~/ 8) % P
    // Recycle `v0`
    final x = v0;
    x.setBigInt(Register25519.PPlus3Slash8BigInt.toBigInt());
    x.pow(x2, x);

    // if (x * x - x2) % P != 0
    v1.mul(x, x);
    v1.sub(v1, x2);
    if (!v1.isZero) {
      // x = x * Z % P
      x.mul(x, Register25519.Z);
    }

    // if (x * x - x2) % P != 0
    v1.mul(x, x);
    v1.sub(v1, x2);
    if (!v1.isZero) {
      return null;
    }

    // if (0x1 & x) != sign
    if ((0x1 & x.data[0]) != sign) {
      // x = P - x
      x.sub(Register25519.P, x);
    }

    // xy = x * y % P
    // Recycle `v1`
    final xy = v1;
    xy.mul(x, y);

    return Ed25519Point(
      x,
      y,
      Register25519.one,
      xy,
    );
  }

  static Ed25519Point _pointMul(
    Register25519 s, // Secret key
    Ed25519Point pointP, // A point
  ) {
    // Construct a new point with value (0, 1, 1, 0)
    var q = Ed25519Point.zero();
    q.y.data[0] = 1;
    q.z.data[0] = 1;

    // Construct a copy of pointP
    pointP = Ed25519Point(
      Register25519.from(pointP.x),
      Register25519.from(pointP.y),
      Register25519.from(pointP.z),
      Register25519.from(pointP.w),
    );

    // Construct two temporary points
    var tmp0 = Ed25519Point.zero();
    final tmp1 = Ed25519Point.zero();

    for (var i = 0; i < 256; i++) {
      // Get n-th bit
      final b = 0x1 & (s.data[i ~/ 16] >> (i % 16));

      if (b == 1) {
        // Q = Q + P
        _pointAdd(tmp0, q, pointP, tmp: tmp1);
        final oldQ = q;
        q = tmp0;
        tmp0 = oldQ;
      }

      // p = P + P
      _pointAdd(tmp0, pointP, pointP, tmp: tmp1);
      final oldP = pointP;
      pointP = tmp0;
      tmp0 = oldP;
    }
    return q;
  }

  static void _setPrivateKeyFixedBits(List<int> list) {
    // The lowest three bits must be 0
    list[0] &= 0xF8;

    // The highest bit must be 0
    list[31] &= 0x7F;

    // The second highest bit must be 1
    list[31] |= 0x40;
  }

  static SecretKey sharedSecretSync(
      {required KeyPairData keyPairData,
      required PublicKey remotePublicKey,
      List<int>? salt}) {
    if (keyPairData is! SimpleKeyPairData ||
        !KeyPairType.ed25519.isValidKeyPairData(keyPairData)) {
      throw ArgumentError.value(
        keyPairData,
        'keyPairData',
      );
    }
    if (remotePublicKey is! SimplePublicKey ||
        !KeyPairType.ed25519.isValidPublicKey(remotePublicKey)) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
      );
    }

    final sharedSecret = _deriveSharedSecret(
        secretKey: keyPairData.bytes,
        remoteKey: remotePublicKey.bytes,
        salt: salt);

    var sha3_256 = SHA3(256, SHA3_PADDING, 256);
    final secretKeyHash = sha3_256.update(sharedSecret).digest();

    return SecretKey(List<int>.unmodifiable(secretKeyHash));
  }

  /// Modifies certain bits of seed so that the result is a valid secret key.
  static Uint8List modifiedPrivateKeyBytes(List<int> seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed must be 32 bytes');
    }
    var sha3_512 = SHA3(512, SHA3_PADDING, 512);
    // Take SHA3_512 hash of the private key.
    final privateKeyHash = sha3_512.update(seed).digest();
    final privateKeyHashFixed = privateKeyHash.sublist(0, 32);
    _setPrivateKeyFixedBits(privateKeyHashFixed);

    return Uint8List.fromList(privateKeyHashFixed);
  }

  static Uint8List _deriveSharedSecret(
      {required List<int> secretKey,
      required List<int> remoteKey,
      List<int>? salt}) {
    final privateKeyBytes = modifiedPrivateKeyBytes(secretKey);

    final unpackedPublicKey = _pointDecompress(remoteKey)!;
    // We get public key by multiplying the modified private key hash with G.
    final pointMul = SiriusEd25519._pointMul(
      Register25519()..setBytes(privateKeyBytes),
      unpackedPublicKey,
    );

    final sharedSecret = _pointCompress(pointMul);

    if (salt != null) {
      for (var i = 0; i < 32; i++) {
        sharedSecret[i] ^= salt[i];
      }
    }

    return Uint8List.fromList(sharedSecret);
  }
}
