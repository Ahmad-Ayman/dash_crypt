/// Implements the Caesar Cipher encryption and decryption algorithm.
/// This is a substitution cipher where each letter in the plaintext
/// is shifted by a fixed number of positions in the alphabet.
class CaesarCipher {
  /// Encrypts the plaintext using the Caesar cipher with the given shift.
  String encrypt({required String plainText, required int shift}) {
    return String.fromCharCodes(plainText.codeUnits.map((char) {
      if (char >= 65 && char <= 90) {
        // Uppercase letters
        return 65 + ((char - 65 + shift) % 26);
      } else if (char >= 97 && char <= 122) {
        // Lowercase letters
        return 97 + ((char - 97 + shift) % 26);
      } else {
        return char; // Non-alphabetic characters remain unchanged
      }
    }));
  }

  /// Decrypts the ciphertext using the Caesar cipher with the given shift.
  String decrypt({required String cipherText, required int shift}) {
    return encrypt(plainText: cipherText, shift: 26 - (shift % 26));
  }
}
