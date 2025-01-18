import 'dart:convert';
import 'dart:typed_data';
import 'package:dash_crypt/src/symmetric/aes/aes_algorithm.dart';

import 'package:dash_crypt/dash_crypt.dart';
import 'package:flutter_test/flutter_test.dart'; // Adjust the import path to match your project structure.

void main() {
  group('AES Encryption Modes Tests', () {
    const testKey = 'sUp3rS3cureKey123!'; // 128-bit key (16 characters)
    const testIV = 'InitializationVec';   // 128-bit IV (16 characters)
    const testPlainText = 'Hello, AES Modes!';
    late String base64Key;
    late String base64IV;

    setUp(() {
      // Correct key and IV sizes
      base64Key = base64.encode(Uint8List(16)); // 128-bit key
      base64IV = base64.encode(Uint8List(16));  // 128-bit IV
    });

    test('AES-128 CBC mode encryption and decryption', () {
      final encrypted = DashCrypt.AES128.encrypt(
        plainText: testPlainText,
        key: base64Key,
        iv: base64IV,
        mode: AESMode.CBC,
      );

      final decrypted = DashCrypt.AES128.decrypt(
        cipherText: encrypted,
        key: base64Key,
        iv: base64IV,
        mode: AESMode.CBC,
      );

      expect(decrypted, equals(testPlainText));
    });

    test('AES-128 GCM mode encryption and decryption', () {
      expect(
            () => DashCrypt.AES128.encrypt(
          plainText: testPlainText,
          key: base64Key,
          iv: base64IV,
          mode: AESMode.GCM,
        ),
        throwsUnimplementedError,
      );
    });

    test('AES-256 CBC mode encryption and decryption', () {
      final base64LongKey = base64.encode(Uint8List(32)); // 256-bit key

      final encrypted = DashCrypt.AES256.encrypt(
        plainText: testPlainText,
        key: base64LongKey,
        iv: base64IV,
        mode: AESMode.CBC,
      );

      final decrypted = DashCrypt.AES256.decrypt(
        cipherText: encrypted,
        key: base64LongKey,
        iv: base64IV,
        mode: AESMode.CBC,
      );

      expect(decrypted, equals(testPlainText));
    });

    test('AES-256 GCM mode encryption and decryption', () {
      expect(
            () => DashCrypt.AES256.encrypt(
          plainText: testPlainText,
          key: base64.encode(Uint8List(32)), // 256-bit key
          iv: base64IV,
          mode: AESMode.GCM,
        ),
        throwsUnimplementedError,
      );
    });


    test('Error handling for invalid key size', () {
      final invalidKey = 'shortKey'; // Invalid size
      final base64InvalidKey = base64.encode(utf8.encode(invalidKey));

      expect(
            () => DashCrypt.AES128.encrypt(
          plainText: testPlainText,
          key: base64InvalidKey,
          iv: base64IV,
          mode: AESMode.CBC,
        ),
        throwsArgumentError,
      );
    });

    test('Error handling for invalid IV size', () {
      final invalidIV = 'shortIV'; // Invalid size
      final base64InvalidIV = base64.encode(utf8.encode(invalidIV));

      expect(
            () => DashCrypt.AES128.encrypt(
          plainText: testPlainText,
          key: base64Key,
          iv: base64InvalidIV,
          mode: AESMode.CBC,
        ),
        throwsArgumentError,
      );
    });
  });
}
