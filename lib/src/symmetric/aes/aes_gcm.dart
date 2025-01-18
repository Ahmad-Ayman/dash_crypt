import 'dart:convert';
import 'dart:typed_data';

import 'aes_key_expansion.dart';
import 'aes_modes.dart';
import 'aes_round_operations.dart';

/// GCM mode implementation.
class AESModeGCM implements AESModeStrategy {
  final int keySize;

  AESModeGCM({required this.keySize});

  @override
  String encrypt(String plaintext, Uint8List key, Uint8List iv) {
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final expandedKey = AESKeyExpansion.expandKey(key);
    final numRounds = _getNumRounds();

    // Step 1: Encrypt plaintext using CTR mode
    final ciphertext = _ctrModeEncrypt(plaintextBytes, expandedKey, numRounds, iv);

    // Step 2: Compute GHASH for authentication
    final authTag = _computeAuthTag(ciphertext, Uint8List(0), expandedKey, numRounds, iv);

    // Combine ciphertext and authentication tag
    return base64.encode(Uint8List.fromList([...ciphertext, ...authTag]));
  }

  @override
  String decrypt(String ciphertext, Uint8List key, Uint8List iv) {
    final ciphertextBytes = base64.decode(ciphertext);
    final authTag = ciphertextBytes.sublist(ciphertextBytes.length - 16);
    final actualCiphertext = ciphertextBytes.sublist(0, ciphertextBytes.length - 16);

    final expandedKey = AESKeyExpansion.expandKey(key);
    final numRounds = _getNumRounds();

    // Verify authentication tag
    final computedTag = _computeAuthTag(actualCiphertext, Uint8List(0), expandedKey, numRounds, iv);
    if (!_constantTimeCompare(authTag, computedTag)) {
      throw ArgumentError('Authentication failed: invalid tag.');
    }

    // Decrypt using CTR mode
    return utf8.decode(_ctrModeEncrypt(actualCiphertext, expandedKey, numRounds, iv));
  }

  Uint8List _ctrModeEncrypt(Uint8List input, Uint8List expandedKey, int numRounds, Uint8List counter) {
    final output = Uint8List(input.length);

    for (var i = 0; i < input.length; i += 16) {
      // Encrypt counter block
      var counterBlock = AESRoundOperations.addRoundKey(counter, expandedKey.sublist(0, 16));
      for (var round = 1; round < numRounds; round++) {
        counterBlock = AESRoundOperations.encryptRound(counterBlock, expandedKey, round);
      }
      counterBlock = AESRoundOperations.finalEncryptRound(counterBlock, expandedKey, numRounds);

      // XOR with input block
      final chunkSize = (i + 16 > input.length) ? input.length - i : 16;
      for (var j = 0; j < chunkSize; j++) {
        output[i + j] = input[i + j] ^ counterBlock[j];
      }

      // Increment counter
      _incrementCounter(counter);
    }

    return output;
  }

  void _incrementCounter(Uint8List counter) {
    for (var i = counter.length - 1; i >= 12; i--) {
      counter[i]++;
      if (counter[i] != 0) break;
    }
  }

  Uint8List _computeAuthTag(Uint8List ciphertext, Uint8List aad, Uint8List expandedKey, int numRounds, Uint8List counter) {
    final hashSubKey = _generateHashSubKey(expandedKey, numRounds);
    final ghashInput = Uint8List.fromList([...aad, ...ciphertext, ..._lengthBlock(aad, ciphertext)]);
    return _ghash(hashSubKey, ghashInput);
  }

  Uint8List _generateHashSubKey(Uint8List expandedKey, int numRounds) {
    final zeroBlock = Uint8List(16);
    var state = AESRoundOperations.addRoundKey(zeroBlock, expandedKey.sublist(0, 16));
    for (var round = 1; round < numRounds; round++) {
      state = AESRoundOperations.encryptRound(state, expandedKey, round);
    }
    return AESRoundOperations.finalEncryptRound(state, expandedKey, numRounds);
  }

  Uint8List _ghash(Uint8List hashSubKey, Uint8List input) {
    final y = Uint8List(16);
    final blockCount = (input.length + 15) ~/ 16;

    for (var i = 0; i < blockCount; i++) {
      final block = input.sublist(i * 16, (i + 1) * 16);
      for (var j = 0; j < 16; j++) {
        y[j] ^= block[j];
      }
      _multiplyInGF128(y, hashSubKey);
    }

    return y;
  }

  void _multiplyInGF128(Uint8List x, Uint8List y) {
    final z = Uint8List(16);
    final v = Uint8List.fromList(y);

    for (var i = 0; i < 128; i++) {
      if ((x[i ~/ 8] & (1 << (7 - (i % 8)))) != 0) {
        for (var j = 0; j < 16; j++) {
          z[j] ^= v[j];
        }
      }

      final carry = v[15] & 1;
      for (var j = 15; j > 0; j--) {
        v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
      }
      v[0] >>= 1;
      if (carry != 0) v[0] ^= 0xe1;
    }

    for (var i = 0; i < 16; i++) {
      x[i] = z[i];
    }
  }

  Uint8List _lengthBlock(Uint8List aad, Uint8List ciphertext) {
    final block = Uint8List(16);
    final aadLen = aad.length * 8;
    final ciphertextLen = ciphertext.length * 8;
    block.buffer.asByteData()
      ..setUint64(0, aadLen, Endian.big)
      ..setUint64(8, ciphertextLen, Endian.big);
    return block;
  }

  bool _constantTimeCompare(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
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