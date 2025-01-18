import 'dart:convert';
import 'dart:typed_data';
import '../../utils/secure_random_utils.dart';
import '../symmetric_algorithm.dart';
import 'aes_cbc.dart';
import 'aes_modes.dart';

/// Supported AES modes.
enum AESMode { CBC, GCM }

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
    final keyBytes = base64.decode(key);
    final ivBytes = iv != null ? base64.decode(iv) : _generateDefaultIV();
    _validateKeySize(keyBytes);
    _validateIVSize(ivBytes);

    return _modeStrategy.encrypt(plaintext, keyBytes, ivBytes);
  }

  @override
  String decrypt(String ciphertext, String key, {String? iv}) {
    final keyBytes = base64.decode(key);
    final ivBytes = iv != null ? base64.decode(iv) : _generateDefaultIV();
    _validateKeySize(keyBytes);
    _validateIVSize(ivBytes);

    return _modeStrategy.decrypt(ciphertext, keyBytes, ivBytes);
  }

  @override
  String generateKey() {
    final rawKey = SecureRandomUtils.generateSecureBytes(keySize ~/ 8);
    return base64.encode(rawKey);
  }

  @override
  String generateIV() {
    return base64.encode(_generateDefaultIV());
  }

  Uint8List _generateDefaultIV() {
    return Uint8List.fromList(SecureRandomUtils.generateSecureBytes(16));
  }

  void _validateKeySizeBits() {
    if (![128, 192, 256].contains(keySize)) {
      throw ArgumentError('Invalid key size. Must be 128, 192, or 256 bits.');
    }
  }

  void _validateKeySize(Uint8List key) {
    if (key.length != keySize ~/ 8) {
      throw ArgumentError('Key size must be ${keySize ~/ 8} bytes for AES-$keySize.');
    }
  }

  void _validateIVSize(Uint8List iv) {
    if (iv.length != 16) {
      throw ArgumentError('IV size must be 16 bytes.');
    }
  }

  AESModeStrategy _initializeModeStrategy() {
    switch (mode) {
      case AESMode.CBC:
        return AESModeCBC(keySize: keySize);
      case AESMode.GCM:
        throw UnimplementedError('GCM mode is not implemented yet.');
      default:
        throw ArgumentError('Unsupported AES mode.');
    }
  }
}
