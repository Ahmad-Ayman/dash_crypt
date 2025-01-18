import 'dart:typed_data';

/// Handles the MixColumns operation for AES encryption and decryption.
class AESMixColumns {
  /// Predefined constants for MixColumns matrix multiplication.
  static const _mixMatrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
  ];

  /// Predefined constants for inverse MixColumns matrix multiplication.
  static const _invMixMatrix = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E],
  ];

  /// Applies the MixColumns operation to the AES state (encryption).
  ///
  /// [state]: A `Uint8List` representing the AES state.
  /// Returns the modified state after MixColumns.
  static Uint8List mixColumns(Uint8List state) {
    _validateState(state);
    return _applyMatrix(state, _mixMatrix);
  }

  /// Applies the inverse MixColumns operation to the AES state (decryption).
  ///
  /// [state]: A `Uint8List` representing the AES state.
  /// Returns the modified state after inverse MixColumns.
  static Uint8List invMixColumns(Uint8List state) {
    _validateState(state);
    return _applyMatrix(state, _invMixMatrix);
  }

  /// Helper function to apply a matrix transformation to the state.
  ///
  /// [state]: A `Uint8List` representing the AES state.
  /// [matrix]: A 4x4 matrix for transformation.
  /// Returns the transformed state.
  static Uint8List _applyMatrix(Uint8List state, List<List<int>> matrix) {
    final transformed = Uint8List(16);
    for (var col = 0; col < 4; col++) {
      for (var row = 0; row < 4; row++) {
        transformed[col * 4 + row] = 0;
        for (var k = 0; k < 4; k++) {
          transformed[col * 4 + row] ^= _galoisMultiply(
            state[col * 4 + k],
            matrix[row][k],
          );
        }
      }
    }
    return transformed;
  }

  /// Validates the AES state to ensure it is 16 bytes.
  static void _validateState(Uint8List state) {
    if (state.length != 16) {
      throw ArgumentError('State must be 16 bytes.');
    }
  }

  /// Performs Galois field multiplication for AES.
  ///
  /// [a]: A byte to multiply.
  /// [b]: A byte to multiply.
  /// Returns the result of the multiplication in GF(2^8).
  static int _galoisMultiply(int a, int b) {
    var result = 0;
    for (var i = 0; i < 8; i++) {
      if ((b & 1) != 0) {
        result ^= a;
      }
      final highBitSet = a & 0x80;
      a = (a << 1) & 0xFF;
      if (highBitSet != 0) {
        a ^= 0x1B; // XOR with the AES irreducible polynomial
      }
      b >>= 1;
    }
    return result;
  }
}
