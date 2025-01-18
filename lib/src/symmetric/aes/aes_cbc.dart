import 'dart:convert';
import 'dart:typed_data';

import 'aes_key_expansion.dart';
import 'aes_modes.dart';
import 'aes_round_operations.dart';

/// CBC mode implementation.
class AESModeCBC implements AESModeStrategy {
  final int keySize;

  AESModeCBC({required this.keySize});

  @override
  String encrypt(String plaintext, Uint8List key, Uint8List iv) {
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final paddedPlaintext = _applyPKCS7Padding(plaintextBytes);

    final expandedKey = AESKeyExpansion.expandKey(key);
    final numRounds = _getNumRounds();

    final ciphertext = Uint8List(paddedPlaintext.length);
    var previousBlock = iv;

    for (var i = 0; i < paddedPlaintext.length; i += 16) {
      final block = paddedPlaintext.sublist(i, i + 16);

      var state = AESRoundOperations.addRoundKey(
        _xorBlocks(block, previousBlock),
        expandedKey.sublist(0, 16),
      );

      for (var round = 1; round < numRounds; round++) {
        state = AESRoundOperations.encryptRound(state, expandedKey, round);
      }

      state = AESRoundOperations.finalEncryptRound(state, expandedKey, numRounds);
      ciphertext.setRange(i, i + 16, state);
      previousBlock = state;
    }

    return base64.encode(ciphertext);
  }

  @override
  String decrypt(String ciphertext, Uint8List key, Uint8List iv) {
    final encryptedBytes = base64.decode(ciphertext);
    final expandedKey = AESKeyExpansion.expandKey(key);
    final numRounds = _getNumRounds();

    final decrypted = Uint8List(encryptedBytes.length);
    var previousBlock = iv;

    for (var i = 0; i < encryptedBytes.length; i += 16) {
      final block = encryptedBytes.sublist(i, i + 16);

      var state = AESRoundOperations.addRoundKey(
        block,
        expandedKey.sublist(numRounds * 16, (numRounds + 1) * 16),
      );

      for (var round = numRounds - 1; round > 0; round--) {
        state = AESRoundOperations.decryptRound(state, expandedKey, round);
      }

      state = AESRoundOperations.finalDecryptRound(state, expandedKey, numRounds);

      final xorBlock = _xorBlocks(state, previousBlock);
      decrypted.setRange(i, i + 16, xorBlock);
      previousBlock = block;
    }

    final unpaddedDecrypted = _removePKCS7Padding(decrypted);
    return utf8.decode(unpaddedDecrypted);
  }

  Uint8List _xorBlocks(Uint8List block1, Uint8List block2) {
    return Uint8List.fromList(
      List<int>.generate(16, (i) => block1[i] ^ block2[i]),
    );
  }

  Uint8List _applyPKCS7Padding(Uint8List data) {
    final paddingLength = 16 - (data.length % 16);
    return Uint8List.fromList([...data, ...List.filled(paddingLength, paddingLength)]);
  }

  Uint8List _removePKCS7Padding(Uint8List data) {
    final paddingLength = data.last;
    if (paddingLength <= 0 || paddingLength > 16) {
      throw ArgumentError('Invalid PKCS7 padding detected.');
    }
    return data.sublist(0, data.length - paddingLength);
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