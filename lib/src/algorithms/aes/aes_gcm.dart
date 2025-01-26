import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import '../../utils/enums.dart';

class Aesgcm {
  final KeySize _keySize;

  Aesgcm({
    required KeySize keySize,
  }) : _keySize = keySize;

  Future<String> encrypt({
    required String text,
    required String key,
    required String iv,
    List<int>? aad,
  }) async {
    final textBytes = utf8.encode(text);
    final keyBytes = _convertKeyToBytes(key);
    final ivBytes = _convertIvToBytes(iv);

    // Validate inputs
    _validateInputs(keyBytes, ivBytes);

    final algorithm = _getAlgorithm();
    final secretKey = SecretKey(keyBytes);

    final secretBox = await algorithm.encrypt(
      textBytes,
      secretKey: secretKey,
      nonce: ivBytes,
      aad: aad ?? <int>[], // Default to an empty list if AAD is missing
    );

    return base64.encode(secretBox.concatenation());
  }

  Future<String> decrypt({
    required String text,
    required String key,
    required String iv,
    List<int>? aad,
  }) async {
    final cipherBytes = base64.decode(text);
    final keyBytes = _convertKeyToBytes(key);
    final ivBytes = _convertIvToBytes(iv);

    // Validate inputs
    _validateInputs(keyBytes, ivBytes);

    final algorithm = _getAlgorithm();
    final secretKey = SecretKey(keyBytes);

    final secretBox = SecretBox.fromConcatenation(
      cipherBytes,
      nonceLength: ivBytes.length,
      macLength: 16, // Authentication tag length is 16 bytes
    );

    final decryptedBytes = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad ?? <int>[], // Default to an empty list if AAD is missing
    );

    return utf8.decode(decryptedBytes);
  }

  Uint8List _convertKeyToBytes(String key) {
    return Uint8List.fromList(utf8.encode(key));
  }

  Uint8List _convertIvToBytes(String iv) {
    return Uint8List.fromList(utf8.encode(iv));
  }

  AesGcm _getAlgorithm() {
    switch (_keySize) {
      case KeySize.aes128:
        return AesGcm.with128bits();
      case KeySize.aes192:
        return AesGcm.with192bits();
      case KeySize.aes256:
        return AesGcm.with256bits();
    }
  }

  void _validateInputs(Uint8List key, Uint8List iv) {
    final expectedKeySize = _getKeySizeInBytes();
    if (key.length != expectedKeySize) {
      throw ArgumentError(
        'Invalid key size: expected $expectedKeySize bytes, but got ${key.length} bytes.',
      );
    }
    if (iv.length != 12) {
      throw ArgumentError(
        'Invalid IV size: expected 12 bytes, but got ${iv.length} bytes.',
      );
    }
  }

  int _getKeySizeInBytes() {
    switch (_keySize) {
      case KeySize.aes128:
        return 16; // 128-bit
      case KeySize.aes192:
        return 24; // 192-bit
      case KeySize.aes256:
        return 32; // 256-bit
    }
  }
}
