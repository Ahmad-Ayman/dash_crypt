import 'dart:typed_data';

/// Handles the ShiftRows and InvShiftRows operations for AES encryption and decryption.
class AESShiftRows {
  /// Applies the ShiftRows operation to the AES state (encryption).
  ///
  /// The first row remains unchanged.
  /// The second row is shifted left by 1 byte.
  /// The third row is shifted left by 2 bytes.
  /// The fourth row is shifted left by 3 bytes.
  ///
  /// [state]: A `Uint8List` of 16 bytes representing the AES state.
  /// Returns the modified state after ShiftRows.
  static Uint8List shiftRows(Uint8List state) {
    if (state.length != 16) {
      throw ArgumentError('State must be 16 bytes.');
    }

    return Uint8List.fromList([
      // Row 0: No shift
      state[0], state[1], state[2], state[3],
      // Row 1: Shift left by 1
      state[5], state[6], state[7], state[4],
      // Row 2: Shift left by 2
      state[10], state[11], state[8], state[9],
      // Row 3: Shift left by 3
      state[15], state[12], state[13], state[14],
    ]);
  }

  /// Applies the inverse ShiftRows operation to the AES state (decryption).
  ///
  /// The first row remains unchanged.
  /// The second row is shifted right by 1 byte.
  /// The third row is shifted right by 2 bytes.
  /// The fourth row is shifted right by 3 bytes.
  ///
  /// [state]: A `Uint8List` of 16 bytes representing the AES state.
  /// Returns the modified state after InvShiftRows.
  static Uint8List invShiftRows(Uint8List state) {
    if (state.length != 16) {
      throw ArgumentError('State must be 16 bytes.');
    }

    return Uint8List.fromList([
      // Row 0: No shift
      state[0], state[1], state[2], state[3],
      // Row 1: Shift right by 1
      state[7], state[4], state[5], state[6],
      // Row 2: Shift right by 2
      state[10], state[11], state[8], state[9],
      // Row 3: Shift right by 3
      state[13], state[14], state[15], state[12],
    ]);
  }
}
