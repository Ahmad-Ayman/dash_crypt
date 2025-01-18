import 'dart:typed_data';
import 'aes_mixcolumns.dart';
import 'aes_substitution.dart';
import 'aes_shiftrows.dart';

/// Handles the various round operations for AES encryption and decryption.
class AESRoundOperations {
  /// Performs the AddRoundKey operation (XORs the state with the round key).
  static Uint8List addRoundKey(Uint8List state, Uint8List roundKey) {
    if (state.length != 16 || roundKey.length != 16) {
      throw ArgumentError('State and round key must each be 16 bytes.');
    }
    return Uint8List.fromList(
      List<int>.generate(state.length, (i) => state[i] ^ roundKey[i]),
    );
  }

  /// Encrypts a single round.
  static Uint8List encryptRound(Uint8List state, Uint8List expandedKey, int round) {
    state = AESSubstitution.subBytes(state);
    state = AESShiftRows.shiftRows(state);
    state = AESMixColumns.mixColumns(state);
    state = addRoundKey(state, expandedKey.sublist(round * 16, (round + 1) * 16));
    return state;
  }

  /// Final encryption round (no MixColumns).
  static Uint8List finalEncryptRound(Uint8List state, Uint8List expandedKey, int numRounds) {
    state = AESSubstitution.subBytes(state);
    state = AESShiftRows.shiftRows(state);
    state = addRoundKey(state, expandedKey.sublist(numRounds * 16, (numRounds + 1) * 16));
    return state;
  }

  /// Decrypts a single round.
  static Uint8List decryptRound(Uint8List state, Uint8List expandedKey, int round) {
    state = AESShiftRows.invShiftRows(state);
    state = AESSubstitution.invSubBytes(state);
    state = addRoundKey(state, expandedKey.sublist(round * 16, (round + 1) * 16));
    state = AESMixColumns.invMixColumns(state);
    return state;
  }

  /// Final decryption round (no InvMixColumns).
  static Uint8List finalDecryptRound(Uint8List state, Uint8List expandedKey, int numRounds) {
    state = AESShiftRows.invShiftRows(state);
    state = AESSubstitution.invSubBytes(state);
    state = addRoundKey(state, expandedKey.sublist(0, 16));
    return state;
  }
}
