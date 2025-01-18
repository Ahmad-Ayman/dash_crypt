import 'dart:convert';
import 'package:dash_crypt/src/symmetric/aes/aes_algorithm.dart';
import 'package:flutter_test/flutter_test.dart';


void main() {
  group('AESAlgorithm Tests', () {
    test('Encrypt and decrypt with AES128', () {
      final aes128 = AESAlgorithm(keySize: 128);
      final key = aes128.generateKey();
      final iv = aes128.generateIV();

      const plaintext = "Hello, AES!";
      final encrypted = aes128.encrypt(plaintext, key, iv: iv);
      final decrypted = aes128.decrypt(encrypted, key, iv: iv);

      expect(decrypted, plaintext);
    });

    test('Encrypt and decrypt with AES192', () {
      final aes192 = AESAlgorithm(keySize: 192);
      final key = aes192.generateKey();
      final iv = aes192.generateIV();

      const plaintext = "Hello, AES!";
      final encrypted = aes192.encrypt(plaintext, key, iv: iv);
      final decrypted = aes192.decrypt(encrypted, key, iv: iv);

      expect(decrypted, plaintext);
    });

    test('Encrypt and decrypt with AES256', () {
      final aes256 = AESAlgorithm(keySize: 256);
      final key = aes256.generateKey();
      final iv = aes256.generateIV();

      const plaintext = "Hello, AES!";
      final encrypted = aes256.encrypt(plaintext, key, iv: iv);
      final decrypted = aes256.decrypt(encrypted, key, iv: iv);

      expect(decrypted, plaintext);
    });

    test('Invalid key size throws error', () {
      final aes128 = AESAlgorithm(keySize: 128);
      const invalidKey = "ShortKey=="; // Not 16 bytes (AES128)

      const plaintext = "Hello, AES!";
      expect(
            () => aes128.encrypt(plaintext, invalidKey),
        throwsArgumentError,
      );
    });

    test('Invalid IV size throws error', () {
      final aes128 = AESAlgorithm(keySize: 128);
      final key = aes128.generateKey();
      const invalidIV = "ShortIV=="; // Not 16 bytes

      const plaintext = "Hello, AES!";
      expect(
            () => aes128.encrypt(plaintext, key, iv: invalidIV),
        throwsArgumentError,
      );
    });

    test('Padding works for non-16-byte plaintext', () {
      final aes128 = AESAlgorithm(keySize: 128);
      final key = aes128.generateKey();
      final iv = aes128.generateIV();

      const plaintext = "Hello!"; // Less than 16 bytes
      final encrypted = aes128.encrypt(plaintext, key, iv: iv);
      final decrypted = aes128.decrypt(encrypted, key, iv: iv);

      expect(decrypted, plaintext);
    });

    test('Empty plaintext encryption throws error', () {
      final aes128 = AESAlgorithm(keySize: 128);
      final key = aes128.generateKey();
      final iv = aes128.generateIV();

      const plaintext = ""; // Empty plaintext
      expect(
            () => aes128.encrypt(plaintext, key, iv: iv),
        throwsArgumentError,
      );
    });

    test('Key and IV generation produces correct lengths', () {
      final aes128 = AESAlgorithm(keySize: 128);
      final key = aes128.generateKey();
      final iv = aes128.generateIV();

      expect(base64.decode(key).length, 16); // AES128 key = 16 bytes
      expect(base64.decode(iv).length, 16); // IV = 16 bytes
    });
  });
}
