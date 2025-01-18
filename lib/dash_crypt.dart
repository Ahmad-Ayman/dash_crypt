import 'dart:convert';

import 'src/symmetric/aes/aes_algorithm.dart';
import 'src/symmetric/aes/aes_modes.dart';
import 'src/utils/secure_random_utils.dart';

/// Centralized entry point for all encryption and decryption operations.
class DashCrypt {
  /// AES-128 Configuration
  static final AES128 = _DashCryptAES(keySize: 128);

  /// AES-192 Configuration
  static final AES192 = _DashCryptAES(keySize: 192);

  /// AES-256 Configuration
  static final AES256 = _DashCryptAES(keySize: 256);

  /// Generates a secure random key for the specified key size (in bits).
  static String generateKey(int keySize) {
    final rawKey = SecureRandomUtils.generateSecureBytes(keySize ~/ 8);
    return base64.encode(rawKey);
  }

  /// Generates a secure random IV.
  static String generateIV() {
    final iv = SecureRandomUtils.generateSecureBytes(16);
    return base64.encode(iv);
  }
}

/// A helper class for AES configurations to support the desired API design.
class _DashCryptAES {
  final int keySize;

  _DashCryptAES({required this.keySize});

  /// Encrypts the given plaintext.
  String encrypt({
    required String plainText,
    required String key,
    required String iv,
    AESMode mode = AESMode.CBC, // Default to CBC mode
  }) {
    final aes = AESAlgorithm(keySize: keySize, mode: mode);
    return aes.encrypt(plainText, key, iv: iv);
  }

  /// Decrypts the given ciphertext.
  String decrypt({
    required String cipherText,
    required String key,
    required String iv,
    AESMode mode = AESMode.CBC, // Default to CBC mode
  }) {
    final aes = AESAlgorithm(keySize: keySize, mode: mode);
    return aes.decrypt(cipherText, key, iv: iv);
  }
}
