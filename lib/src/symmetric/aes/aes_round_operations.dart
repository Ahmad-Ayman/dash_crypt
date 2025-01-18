import 'dart:typed_data';

import 'aes_mixcolumns.dart'; // For MixColumns and InvMixColumns
import 'aes_shiftrows.dart'; // For ShiftRows and InvShiftRows
import 'aes_substitution.dart'; // For SubBytes and InvSubBytes

/// Handles AES round operations for encryption and decryption.
class AESRoundOperations {
  /// Adds the round key to the state by XORing it with the round key.
  static Uint8List addRoundKey(Uint8List state, Uint8List roundKey) {
    if (state.length != 16 || roundKey.length != 16) {
      print("State: ${state.length} bytes, RoundKey: ${roundKey.length} bytes");
      throw ArgumentError('State and round key must each be 16 bytes.');
    }
    return Uint8List.fromList(
      List.generate(state.length, (i) => state[i] ^ roundKey[i]),
    );
  }

  /// Performs a single encryption round.
  static Uint8List encryptRound(
      Uint8List state, Uint8List expandedKey, int round) {
    state = AESSubstitution.subBytes(state);
    state = AESShiftRows.shiftRows(state);
    state = AESMixColumns.mixColumns(state);
    state =
        addRoundKey(state, expandedKey.sublist(round * 16, (round + 1) * 16));
    return state;
  }

  /// Performs the final encryption round (no MixColumns).
  static Uint8List finalEncryptRound(
      Uint8List state, Uint8List expandedKey, int numRounds) {
    state = AESSubstitution.subBytes(state);
    state = AESShiftRows.shiftRows(state);
    state = addRoundKey(
        state, expandedKey.sublist(numRounds * 16, (numRounds + 1) * 16));
    return state;
  }

  /// Performs a single decryption round.
  static Uint8List decryptRound(
      Uint8List state, Uint8List expandedKey, int round) {
    state = AESShiftRows.invShiftRows(state);
    state = AESSubstitution.invSubBytes(state);
    state =
        addRoundKey(state, expandedKey.sublist(round * 16, (round + 1) * 16));
    state = AESMixColumns.invMixColumns(state);
    return state;
  }

  /// Performs the final decryption round (no InvMixColumns).
  static Uint8List finalDecryptRound(
      Uint8List state, Uint8List expandedKey, int numRounds) {
    state = AESShiftRows.invShiftRows(state);
    state = AESSubstitution.invSubBytes(state);
    state = addRoundKey(state, expandedKey.sublist(0, 16));
    return state;
  }
}
