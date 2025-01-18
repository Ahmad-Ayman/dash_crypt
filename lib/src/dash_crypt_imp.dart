import 'dart:convert';

import 'package:dash_crypt/src/classical/affine_cipher.dart';
import 'package:dash_crypt/src/symmetric/aes/aes_algorithm.dart';
import 'package:dash_crypt/src/symmetric/aes/aes_constants.dart';
import 'package:dash_crypt/src/utils/secure_random_utils.dart';

import '../dash_crypt.dart';
import 'classical/classical_index.dart';

/// Centralized entry point for all encryption and decryption operations.
class DashCrypt {
  /// AES-128 Configuration
  static final AES128 = _DashCryptAES(keySize: 128);

  /// AES-192 Configuration
  static final AES192 = _DashCryptAES(keySize: 192);

  /// AES-256 Configuration
  static final AES256 = _DashCryptAES(keySize: 256);

  // Classical cipher implementations
  static final Caesar = CaesarCipher();
  static final Vigenere = VigenereCipher();
  static final Monoalphabetic = MonoalphabeticCipher();
  static final ColumnarTransposition = ColumnarTranspositionCipher();
  static final Playfair = PlayfairCipher();
  static final RailFence = RailFenceCipher();
  static final Affine = AffineCipher();

  /// Generates a secure random key for the specified key size (in bits).
  static String generateKey(int keySize) {
    if (!AESConstants.validKeySizes.contains(keySize)) {
      throw ArgumentError(
          'Invalid key size. Must be one of ${AESConstants.validKeySizes} bits.');
    }
    final rawKey = SecureRandomUtils.generateSecureKey(keySize);
    return base64.encode(rawKey);
  }

  /// Generates a secure random IV.
  static String generateIV(int ivSize) {
    if (ivSize <= 0) {
      throw ArgumentError('IV size must be a positive integer.');
    }
    final iv = SecureRandomUtils.generateSecureIV(ivSize);
    return base64.encode(iv);
  }
}

/// A helper class for AES configurations to support fluent API.
class _DashCryptAES {
  final int keySize;

  _DashCryptAES({required this.keySize});

  /// Encrypts the given plaintext.
  String encrypt({
    required String plainText,
    required String key,
    String? iv,
    required AESMode mode,
  }) {
    // Assert that IV is provided for CBC and GCM modes, and null otherwise
    assert(
      (mode == AESMode.CBC || mode == AESMode.GCM) ? iv != null : iv == null,
      'IV must be provided for CBC and GCM modes, and null for ECB mode.',
    );

    final aes = AESAlgorithm(keySize: keySize, mode: mode);
    return aes.encrypt(plainText, key, iv: iv);
  }

  /// Decrypts the given ciphertext.
  String decrypt({
    required String cipherText,
    required String key,
    String? iv,
    required AESMode mode,
  }) {
    // Assert that IV is provided for CBC and GCM modes, and null otherwise
    assert(
      (mode == AESMode.CBC || mode == AESMode.GCM) ? iv != null : iv == null,
      'IV must be provided for CBC and GCM modes, and null for ECB mode.',
    );

    final aes = AESAlgorithm(keySize: keySize, mode: mode);
    return aes.decrypt(cipherText, key, iv: iv);
  }
}
