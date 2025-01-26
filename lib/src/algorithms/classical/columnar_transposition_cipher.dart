/// Implements the Transposition Cipher encryption and decryption algorithm.
/// Rearranges the characters of the plaintext based on a numberOfColumns.
class ColumnarTranspositionCipher {
  /// Encrypts the plaintext using the Transposition cipher with the given numberOfColumns.
  String encrypt({required String text, required int numberOfColumns}) {
    final paddedLength = (text.length + numberOfColumns - 1) ~/ numberOfColumns * numberOfColumns;
    final paddedText = text.padRight(paddedLength, ' ');

    final chunks = List.generate(numberOfColumns, (col) {
      return String.fromCharCodes(
          List.generate(paddedText.length ~/ numberOfColumns, (row) {
        return paddedText.codeUnitAt(row * numberOfColumns + col);
      }));
    });

    return chunks.join();
  }

  /// Decrypts the ciphertext using the Transposition cipher with the given numberOfColumns.
  String decrypt({required String text, required int numberOfColumns}) {
    final numRows = text.length ~/ numberOfColumns;
    final columns = List.generate(numberOfColumns, (col) {
      return text.substring(col * numRows, (col + 1) * numRows);
    });

    final decrypted = StringBuffer();
    for (int i = 0; i < numRows; i++) {
      for (int j = 0; j < numberOfColumns; j++) {
        decrypted.write(columns[j][i]);
      }
    }
    return decrypted.toString().trimRight();
  }
}
