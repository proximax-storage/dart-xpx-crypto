import 'package:xpx_crypto/xpx_crypto.dart' as crypto;

void main() {
  const plainTextMessage = 'Hello from Dart Sirius crypto sdk';

  const senderPrivateKey = 'B38A1490B33A4BD718ABB0A1BEF389CAE07A435F3DEC39BC518D84B1ABF8531B';
  const senderPublicKey = '10C81B5AD435CFA5D21CFACC519575168AF44F7F495EFF8B288BC92A455DCDA3';

  const recipientPrivateKey = '69441d693502557fa37b3d030bf997425d8bd60e3d42f8a404aa14798ae97bea';
  const recipientPublicKey = '3DE5BAAAE21CD246181D2B3A6C06E6502EE10C515322AA045FB6B919B590718C';

  final String encryptMessage = crypto.encryptMessage(plainTextMessage, senderPrivateKey, recipientPublicKey);

  print('encryptMessage: $encryptMessage');

  final String decryptMessage = crypto.decryptMessage(encryptMessage, recipientPrivateKey, senderPublicKey);

  print('plainTextMessage: $decryptMessage');
}
