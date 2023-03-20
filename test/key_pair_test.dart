library xpx_crypto.test.key_pair_test;

import 'dart:typed_data' show Uint8List;
import 'package:cryptography/helpers.dart';
import 'package:hex/hex.dart';

import 'package:xpx_crypto/xpx_crypto.dart' show KeyPair, Signature, listsEqual;
import 'package:test/test.dart';

void main() {
  const TEST_PRIVATE_KEYS = <String>[
    '575DBB3062267EFF57C970A336EBBC8FBCFE12C5BD3ED7BC11EB0481D7704CED',
    '5B0E3FA5D3B49A79022D7C1E121BA1CBBF4DB5821F47AB8C708EF88DEFC29BFE',
    '738BA9BB9110AEA8F15CAA353ACA5653B4BDFCA1DB9F34D0EFED2CE1325AEEDA',
    'E8BF9BC0F35C12D8C8BF94DD3A8B5B4034F1063948E3CC5304E55E31AA4B95A6',
    'C325EA529674396DB5675939E7988883D59A5FC17A28CA977E3BA85370232A83'
  ];

  const SIRIUS_PRIVATE_KEY = <String>[
    'abf4cf55a2b3f742d7543d9cc17f50447b969e6e06f5ea9195d428ab12b7318d',
    '6aa6dad25d3acb3385d5643293133936cdddd7f7e11818771db1ff2f9d3f9215',
    '8e32bc030a4c53de782ec75ba7d5e25e64a2a072a56e5170b77a4924ef3c32a9',
    'c83ce30fcb5b81a51ba58ff827ccbc0142d61c13e2ed39e78e876605da16d8d7',
    '2da2a0aae0f37235957b51d15843edde348a559692d8fa87b94848459899fc27',
  ];

  const INPUT_DATA = <String>[
    '8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9',
    'e4a92208a6fc52282b620699191ee6fb9cf04daf48b48fd542c5e43daa9897763a199aaa4b6f10546109f47ac3564fade0',
    '13ed795344c4448a3b256f23665336645a853c5c44dbff6db1b9224b5303b6447fbf8240a2249c55',
    'a2704638434e9f7340f22d08019c4c8e3dbee0df8dd4454a1d70844de11694f4c8ca67fdcb08fed0cec9abb2112b5e5f89',
    'd2488e854dbcdfdb2c9d16c8c0b2fdbc0abb6bac991bfe2b14d359a6bc99d66c00fd60d731ae06d0'
  ];

  const EXPECTED_SIGNATURES = <String>[
    '26e2c18bd0865ac141edc181c61d2ec74231a4c8eb644c732d4830e82eb143094e7078086648964b0b91363e555907ec53e2ae7bd185d609805099f5c3a4cf07',
    '079b761e8c6a0af15664d86e8dccc67d78286384732cf3e36332e7e839dab617c4a7f942b9c40f84513613089011378b43d43706648317564e3f77ef142f280a',
    '2ad313e2bffe35a6afbbcbc1ac673922eb760ec1ff91c35baa76275e4e9ba3d9a5fa7f5b005d52f5e3b9db381dd268499234c7f0774c297823693955c382d00b',
    'c846a755cf670a8c13861d27380568480ffc96d99ca2f560ec432dee244d41d7b180ec6b756ed393a249c28932d6ce1bd5a3a7d28396deba7739baef611a180b',
    'df852fb53bf166acf784e2c906bfe35aa0a7d51a0193265288945111d066906c77874ad1e13555e274a4425673af046b102137ade1df5a361614c7411b53f50f'
  ];

  const EXPECTED_PUBLIC_KEYS = <String>[
    'BD8D3F8B7E1B3839C650F458234AB1FF87CDB1EDA36338D9E446E27D454717F2',
    '26821636A618FD524A3AB57276EFC36CAF787DF19EE00F60035CE376A18E8C47',
    'DFC7F40FC549AC8BB2EF097600103FF457A1D7DC5755D434474761459B030E6F',
    '96C7AB358EBB91104322C56435642BD939A77432286B229372987FC366EA319F',
    '9488CFB5D7D439213B11FA80C1B57E8A7AB7E41B64CBA18A89180D412C04915C'
  ];

  // ---------------------------
  // ---- KeyPair creation -----
  // ---------------------------
  group('construction', () {
    test('can create a new random key pair - SHA3', () async {
      final keyPair = await KeyPair.random();

      expect(keyPair, isNotNull);
      expect(keyPair.secretKey, isNotNull);
      expect(keyPair.publicKey, isNotNull);
      expect(HEX.encode(keyPair.secretKey).length == 64, isTrue);
      expect(HEX.encode(keyPair.publicKey).length == 64, isTrue);
    });

    test('can extract from private key test vectors', () async {
      // Sanity check
      expect(TEST_PRIVATE_KEYS.length, equals(EXPECTED_PUBLIC_KEYS.length));

      for (int i = 0; i < TEST_PRIVATE_KEYS.length; i++) {
        // Prepare
        final String privateKeyHex = TEST_PRIVATE_KEYS[i];
        final String expectedPublicKey = EXPECTED_PUBLIC_KEYS[i];
        final KeyPair keyPair = await KeyPair.fromPrivateKey(privateKeyHex);

        // Assert
        final String actualPubKey = HEX.encode(keyPair.publicKey).toUpperCase();
        final String actualPrivateKey = HEX.encode(keyPair.secretKey).toUpperCase();
        expect(actualPubKey, equals(expectedPublicKey));
        expect(actualPrivateKey, equals(privateKeyHex));
      }
    });

    test('cannot extract from invalid private key', () {
      final List<String> INVALID_KEYS = [
        '', // empty
        '53C659B47C176A70EB228DE5C0A0FF391282C96640C2A42CD5BBD0982176AB', // too short
        '53C659B47C176A70EB228DE5C0A0FF391282C96640C2A42CD5BBD0982176AB1BBB' // too long
      ];

      for (var invalidPrivateKey in INVALID_KEYS) {
        final List<int> privateKeySeed = HEX.decode(invalidPrivateKey);
        expect(
            () async => await KeyPair.fromPrivateKey(invalidPrivateKey),
            throwsA(predicate((e) =>
                e is ArgumentError &&
                e.message ==
                    'Private key has an unexpected size. '
                        'Expected: 32, Got: ${privateKeySeed.length}')));
      }
    });

    test('can create the same keypair from private key', () async {
      final keyPair1 = await KeyPair.fromPrivateKey(TEST_PRIVATE_KEYS[0]);
      final keyPair2 = await KeyPair.fromPrivateKey(TEST_PRIVATE_KEYS[0]);

      expect(keyPair1.hashCode, isNotNull);
      expect(keyPair2.hashCode, isNotNull);
      expect(keyPair1.secretKey, equals(keyPair2.secretKey));
      expect(keyPair1.publicKey, equals(keyPair2.publicKey));
      expect(keyPair1 == keyPair2, isTrue);
    });

    // test('can extract a public key from a private key seed', () {
    //   final List<int> privateKeySeed = HEX.decode(TEST_PRIVATE_KEYS[0]);
    //   final Uint8List extractedPublicKey = CryptoUtils.extractPublicKey(privateKeySeed);
    //
    //   final List<int> expected = HEX.decode(EXPECTED_PUBLIC_KEYS[0]);
    //   expect(ArrayUtils.deepEqual(extractedPublicKey, expected), isTrue);
    //
    //   final String extractedPublicKeyHex = HEX.encode(extractedPublicKey);
    //   expect(extractedPublicKeyHex.toUpperCase(), equals(EXPECTED_PUBLIC_KEYS[0]));
    // });

    test('cannot extract a public key from an invalid private key seed', () {
      // null seed
      expect(() async => await KeyPair.extractPublicKey([]),
          throwsA(predicate((e) => e is ArgumentError && e.message.toString().contains('Must not be empty'))));

      // incorrect length
      expect(() async => await KeyPair.extractPublicKey(Uint8List(31)),
          throwsA(predicate((e) => e is ArgumentError && e.message.toString().contains('Seed must have 32 bytes'))));
      expect(() async => await KeyPair.extractPublicKey(Uint8List(34)),
          throwsA(predicate((e) => e is ArgumentError && e.message.toString().contains('Seed must have 32 bytes'))));
    });

    test('can wipe a key using a util function wipe()', () async {
      final KeyPair keyPair = await KeyPair.random();
      expect(keyPair.secretKey, isNotNull);
      expect(keyPair.secretKey[0] != 0, isTrue);
      expect(keyPair.secretKey[keyPair.secretKey.length - 1] != 0, isTrue);

      // wipe
      _wipe(keyPair.secretKey);
      expect(keyPair.secretKey, isNotNull);
      for (var byte in keyPair.secretKey) {
        expect(byte == 0, isTrue);
      }
    });

    test('can put and extract hex formatted key with leading zeros', () async {
      const String hex = '00137c7c32881d1fff2e905f5b7034bcbcdb806d232f351db48a7816285c548f';
      final KeyPair keyPair = await KeyPair.fromPrivateKey(hex);
      final String actual = HEX.encode(keyPair.secretKey);

      expect(actual, equals(hex));
    });
  });

  // ---------------------------
  // --------- Signing ---------
  // ---------------------------
  group('sign', () {
    test('fills the signature', () async {
      // Prepare
      final KeyPair keyPair = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair.sign(payload);

      // Assert
      final Uint8List emptySig = Uint8List(32);
      expect(listsEqual(signature.bytes, emptySig), false);
    });

    test('returns same signature for same data signed by same key pairs', () async {
      // Prepare
      final String privateKey = HEX.encode(getRandomBytes(32));
      final KeyPair keyPair1 = await KeyPair.fromPrivateKey(privateKey);
      final KeyPair keyPair2 = await KeyPair.fromPrivateKey(privateKey);
      final Uint8List payload = getRandomBytes(100);

      final Signature signature1 = await keyPair1.sign(payload);
      final Signature signature2 = await keyPair2.sign(payload);

      // Assert
      expect(listsEqual(signature1.bytes, signature2.bytes), true);
    });

    test('returns different signature for data signed by different key pairs', () async {
      // Prepare
      final KeyPair keyPair1 = await KeyPair.random();
      final KeyPair keyPair2 = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);

      final Signature signature1 = await keyPair1.sign(payload);
      final Signature signature2 = await keyPair2.sign(payload);

      // Assert
      expect(listsEqual(signature1.bytes, signature2.bytes), false);
    });
  });

  // ---------------------------
  // --------- Verify ----------
  // ---------------------------
  group('verify', () {
    test('returns true for data signed with same key pair', () async {
      // Prepare
      final KeyPair keyPair = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair.sign(payload);

      final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

      // Assert
      expect(isVerified, true);
    });

    test('returns false for data signed with different a different key pair', () async {
      final KeyPair keyPair1 = await KeyPair.random();
      final KeyPair keyPair2 = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair1.sign(payload);

      final bool isVerified = await KeyPair.verify(publicKey: keyPair2.publicKey, data: payload, signature: signature);

      // Assert
      expect(isVerified, isFalse);
    });

    test('returns false if signature has been modified', () async {
      final KeyPair keyPair = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);

      for (int i = 0; i < 64; i += 4) {
        final Signature signature = await keyPair.sign(payload);
        signature.bytes[i] ^= 0xFF; // modify signature

        final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

        // Assert
        expect(isVerified, isFalse);
      }
    });

    test('returns false if payload has been modified', () async {
      final KeyPair keyPair = await KeyPair.random();
      final Uint8List payload = getRandomBytes(44);

      for (int i = 0; i < payload.length; i += 4) {
        final Signature signature = await keyPair.sign(payload);
        payload[i] ^= 0xFF; // modify payload

        final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

        // Assert
        expect(isVerified, isFalse);
      }
    });

    test('fails if public key is not on curve', () async {
      final KeyPair keyPair = await KeyPair.random();
      keyPair.publicKey.fillRange(0, keyPair.publicKey.length, 0);
      keyPair.publicKey[keyPair.publicKey.length - 1] = 1;

      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair.sign(payload);

      final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

      // Assert
      expect(isVerified, isFalse);
    });

    test('fails if public key does not correspond to private key', () async {
      final KeyPair keyPair = await KeyPair.random();
      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair.sign(payload);

      // Alter public key
      for (int i = 0; i < keyPair.publicKey.length; i++) {
        keyPair.publicKey[i] ^= 0xFF;
      }

      final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

      // Assert
      expect(isVerified, isFalse);
    });

    test('rejects zero public key', () async {
      final KeyPair keyPair = await KeyPair.random();
      keyPair.publicKey.fillRange(0, keyPair.publicKey.length, 0);

      final Uint8List payload = getRandomBytes(100);
      final Signature signature = await keyPair.sign(payload);

      final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: payload, signature: signature);

      // Assert
      expect(isVerified, isFalse);
    });

  });

  // ---------------------------
  // ------ Test vectors -------
  // ---------------------------
  group('test vectors', () {
    // @see https://github.com/nemtech/test-vectors/blob/master/2.test-sign.json
    test('can sign test vectors', () async {
      // Sanity check
      expect(SIRIUS_PRIVATE_KEY.length, equals(INPUT_DATA.length));
      expect(SIRIUS_PRIVATE_KEY.length, equals(EXPECTED_SIGNATURES.length));

      for (int i = 0; i < SIRIUS_PRIVATE_KEY.length; i++) {
        // Prepare
        final KeyPair keyPair = await KeyPair.fromPrivateKey(SIRIUS_PRIVATE_KEY[i]);
        final Uint8List inputData = Uint8List.fromList(HEX.decode(INPUT_DATA[i]));
        final Signature signature = await keyPair.sign(inputData);

        // Assert
        final String result = HEX.encode(signature.bytes);
        expect(result, equals(EXPECTED_SIGNATURES[i]));
      }
    });

    test('can verify test vectors', () async {
      // Sanity check
      expect(SIRIUS_PRIVATE_KEY.length, equals(INPUT_DATA.length));
      expect(SIRIUS_PRIVATE_KEY.length, equals(EXPECTED_SIGNATURES.length));

      for (int i = 0; i < SIRIUS_PRIVATE_KEY.length; i++) {
        // Prepare
        final KeyPair keyPair = await KeyPair.fromPrivateKey(SIRIUS_PRIVATE_KEY[i]);
        final Uint8List inputData = Uint8List.fromList(HEX.decode(INPUT_DATA[i]));
        final Signature signature = await keyPair.sign( inputData);

        final bool isVerified = await KeyPair.verify(publicKey: keyPair.publicKey, data: inputData, signature: signature);

        // Assert
        expect(isVerified, isTrue);
      }
    });
  });
}

/// Wipes the value of given [byte].
void _wipe(Uint8List byte) {
  for (int i = 0; i < byte.length; i++) {
    byte[i] = 0;
  }
}

Uint8List getRandomBytes(int size) {
  var payload = Uint8List(size);
  fillBytesWithSecureRandom(payload);
  return payload;
}
