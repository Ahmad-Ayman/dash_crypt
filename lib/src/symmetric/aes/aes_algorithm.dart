import 'dart:convert';
import 'dart:typed_data';

import 'package:dash_crypt/src/symmetric/aes/aes_gcm.dart';

import '../../utils/enums.dart';
import '../../utils/secure_random_utils.dart';
import '../symmetric_algorithm.dart';
import 'aes_cbc.dart';
import 'aes_ecb.dart';
import 'aes_modes.dart';

/// Implements AES encryption and decryption for AES-128, AES-192, and AES-256.
class AESAlgorithm implements SymmetricAlgorithm {
  final int keySize;
  final AESMode mode;
  late final AESModeStrategy _modeStrategy;

  AESAlgorithm({required this.keySize, this.mode = AESMode.CBC}) {
    _validateKeySizeBits();
    _modeStrategy = _initializeModeStrategy();
  }

  @override
  String encrypt(String plaintext, String key, {String? iv}) {
    final normalizedKey = _normalizeKey(key);
    final keyBytes = base64.decode(normalizedKey);

    final normalizedIV = _normalizeIV(iv);
    final ivBytes = Uint8List.fromList(utf8.encode(normalizedIV));

    _validateKeySize(keyBytes);
    _validateIV(normalizedIV);

    return _modeStrategy.encrypt(plaintext, keyBytes, ivBytes);
  }

  @override
  String decrypt(String ciphertext, String key, {String? iv}) {
    final normalizedKey = _normalizeKey(key);
    final keyBytes = base64.decode(normalizedKey);

    final normalizedIV = _normalizeIV(iv);
    final ivBytes = Uint8List.fromList(utf8.encode(normalizedIV));

    _validateKeySize(keyBytes);
    _validateIV(normalizedIV);

    return _modeStrategy.decrypt(ciphertext, keyBytes, ivBytes);
  }

  /// Normalizes the IV to the correct length based on the mode.
  String _normalizeIV(String? iv) {
    final requiredLength =
        mode == AESMode.GCM ? 12 : 16; // GCM: 12 bytes, CBC: 16 bytes
    if (iv == null) {
      return '0' * requiredLength; // Generate a default IV if none provided
    } else if (iv.length < requiredLength) {
      return iv.padRight(requiredLength, '0'); // Pad IV if too short
    } else if (iv.length > requiredLength) {
      return iv.substring(0, requiredLength); // Truncate IV if too long
    }
    return iv; // Return as is if the length is correct
  }

  @override
  String generateKey() {
    final rawKey = SecureRandomUtils.generateSecureBytes(keySize ~/ 8);
    return base64.encode(rawKey);
  }

  @override
  String generateIV() {
    final requiredLength = mode == AESMode.GCM ? 12 : 16;
    final rawIV = SecureRandomUtils.generateSecureBytes(requiredLength);
    return utf8.decode(rawIV);
  }

  String _normalizeKey(String key) {
    final keyBytes = utf8.encode(key);
    if (keyBytes.length == keySize ~/ 8) {
      // If key matches the required size, use as is
      return base64.encode(keyBytes);
    } else if (keyBytes.length > keySize ~/ 8) {
      // Truncate the key
      return base64.encode(keyBytes.sublist(0, keySize ~/ 8));
    } else {
      // Pad the key
      final paddedKey = Uint8List.fromList(
        keyBytes + List.filled((keySize ~/ 8) - keyBytes.length, 0),
      );
      return base64.encode(paddedKey);
    }
  }

  void _validateKeySizeBits() {
    if (![128, 192, 256].contains(keySize)) {
      throw ArgumentError('Invalid key size. Must be 128, 192, or 256 bits.');
    }
  }

  void _validateKeySize(Uint8List key) {
    if (key.length != keySize ~/ 8) {
      throw ArgumentError(
          'Key size must be ${keySize ~/ 8} bytes for AES-$keySize.');
    }
  }

  void _validateIV(String iv) {
    final requiredLength =
        mode == AESMode.GCM ? 12 : 16; // GCM: 12 bytes, CBC: 16 bytes
    if (iv.length != requiredLength) {
      throw ArgumentError(
          'IV size must be $requiredLength bytes for AES-${mode.name}.');
    }
  }

  AESModeStrategy _initializeModeStrategy() {
    switch (mode) {
      case AESMode.CBC:
        return AESModeCBC(keySize: keySize);
      case AESMode.GCM:
        return AESModeGCM(keySize: keySize);
      case AESMode.ECB:
        return AESModeECB(keySize: keySize);
      default:
        throw ArgumentError('Unsupported AES mode.');
    }
  }
}
