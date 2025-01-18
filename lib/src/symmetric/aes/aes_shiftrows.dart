import 'dart:typed_data';

/// Handles the ShiftRows operation for AES encryption and decryption.
class AESShiftRows {
  /// Applies the ShiftRows operation to the AES state (encryption).
  static Uint8List shiftRows(Uint8List state) {
    if (state.length != 16) {
      throw ArgumentError('State must be 16 bytes.');
    }

    return Uint8List.fromList([
      state[0], state[5], state[10], state[15],
      state[4], state[9], state[14], state[3],
      state[8], state[13], state[2], state[7],
      state[12], state[1], state[6], state[11],
    ]);
  }

  /// Applies the inverse ShiftRows operation to the AES state (decryption).
  static Uint8List invShiftRows(Uint8List state) {
    if (state.length != 16) {
      throw ArgumentError('State must be 16 bytes.');
    }

    return Uint8List.fromList([
      state[0], state[13], state[10], state[7],
      state[4], state[1], state[14], state[11],
      state[8], state[5], state[2], state[15],
      state[12], state[9], state[6], state[3],
    ]);
  }
}
