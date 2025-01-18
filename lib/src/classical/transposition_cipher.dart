/// Implements the Transposition Cipher encryption and decryption algorithm.
/// Rearranges the characters of the plaintext based on a key.
class ColumnarTranspositionCipher {
  /// Encrypts the plaintext using the Transposition cipher with the given key.
  String encrypt({required String plainText, required int key}) {
    final paddedLength = (plainText.length + key - 1) ~/ key * key;
    final paddedText = plainText.padRight(paddedLength, ' ');

    final chunks = List.generate(key, (col) {
      return String.fromCharCodes(
          List.generate(paddedText.length ~/ key, (row) {
        return paddedText.codeUnitAt(row * key + col);
      }));
    });

    return chunks.join();
  }

  /// Decrypts the ciphertext using the Transposition cipher with the given key.
  String decrypt({required String cipherText, required int key}) {
    final numRows = cipherText.length ~/ key;
    final columns = List.generate(key, (col) {
      return cipherText.substring(col * numRows, (col + 1) * numRows);
    });

    final decrypted = StringBuffer();
    for (int i = 0; i < numRows; i++) {
      for (int j = 0; j < key; j++) {
        decrypted.write(columns[j][i]);
      }
    }
    return decrypted.toString().trimRight();
  }
}
