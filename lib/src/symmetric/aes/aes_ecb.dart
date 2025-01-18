import 'dart:convert';
import 'dart:typed_data';

import 'aes_key_expansion.dart';
import 'aes_modes.dart';
import 'aes_round_operations.dart';

/// ECB mode implementation.
class AESModeECB implements AESModeStrategy {
  final int keySize;

  AESModeECB({required this.keySize});

  @override
  String encrypt(String plaintext, Uint8List key, Uint8List iv) {
    // ECB mode doesn't use IV, ignore it
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final paddedPlaintext = _applyPKCS7Padding(plaintextBytes);

    final expandedKey = Uint8List.fromList(AESKeyExpansion.expandKey(key));
    final numRounds = _getNumRounds();

    final ciphertext = Uint8List(paddedPlaintext.length);

    for (var i = 0; i < paddedPlaintext.length; i += 16) {
      final block = paddedPlaintext.sublist(i, i + 16);

      // Perform encryption rounds
      var state = AESRoundOperations.addRoundKey(
        block,
        expandedKey.sublist(0, 16),
      );
      for (var round = 1; round < numRounds; round++) {
        state = AESRoundOperations.encryptRound(state, expandedKey, round);
      }
      state =
          AESRoundOperations.finalEncryptRound(state, expandedKey, numRounds);

      ciphertext.setRange(i, i + 16, state);
    }

    return base64.encode(ciphertext);
  }

  @override
  String decrypt(String ciphertext, Uint8List key, Uint8List iv) {
    // ECB mode doesn't use IV, ignore it
    final encryptedBytes = base64.decode(ciphertext);
    final expandedKey = Uint8List.fromList(AESKeyExpansion.expandKey(key));
    final numRounds = _getNumRounds();

    if (encryptedBytes.isEmpty || encryptedBytes.length % 16 != 0) {
      throw ArgumentError('Invalid ciphertext length for AES-ECB.');
    }

    final decrypted = Uint8List(encryptedBytes.length);

    for (var i = 0; i < encryptedBytes.length; i += 16) {
      final block = encryptedBytes.sublist(i, i + 16);

      // Perform decryption rounds
      var state = AESRoundOperations.addRoundKey(
        block,
        expandedKey.sublist(numRounds * 16, (numRounds + 1) * 16),
      );
      for (var round = numRounds - 1; round > 0; round--) {
        state = AESRoundOperations.decryptRound(state, expandedKey, round);
      }
      state =
          AESRoundOperations.finalDecryptRound(state, expandedKey, numRounds);

      decrypted.setRange(i, i + 16, state);
    }

    return _removePKCS7Padding(decrypted);
  }

  Uint8List _applyPKCS7Padding(Uint8List data) {
    final paddingLength = 16 - (data.length % 16);
    return Uint8List.fromList(
        [...data, ...List.filled(paddingLength, paddingLength)]);
  }

  String _removePKCS7Padding(Uint8List data) {
    if (data.isEmpty || data.length % 16 != 0) {
      throw ArgumentError('Invalid ciphertext length for PKCS7 padding.');
    }

    final paddingLength = data.last;
    if (paddingLength <= 0 || paddingLength > 16) {
      throw ArgumentError('Invalid PKCS7 padding detected.');
    }

    // Verify padding bytes are valid
    final paddingBytes = data.sublist(data.length - paddingLength);
    if (paddingBytes.any((byte) => byte != paddingLength)) {
      throw ArgumentError('Invalid PKCS7 padding detected.');
    }

    return utf8.decode(data.sublist(0, data.length - paddingLength));
  }

  int _getNumRounds() {
    switch (keySize) {
      case 128:
        return 10;
      case 192:
        return 12;
      case 256:
        return 14;
      default:
        throw ArgumentError('Invalid key size.');
    }
  }
}
