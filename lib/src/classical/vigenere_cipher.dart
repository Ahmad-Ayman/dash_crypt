import 'package:dash_crypt/src/utils/extensions.dart';

/// Implements the Vigenère Cipher encryption and decryption algorithm.
/// This is a polyalphabetic substitution cipher where each letter
/// is shifted based on a repeating key.
class VigenereCipher {
  /// Encrypts the plaintext using the Vigenère cipher with the given key.
  String encrypt({required String plainText, required String key}) {
    key = key.toLowerCase();
    return String.fromCharCodes(plainText.codeUnits.mapIndexed((index, char) {
      if (char >= 65 && char <= 90) {
        // Uppercase letters
        return 65 +
            ((char - 65 + key.codeUnitAt(index % key.length) - 97) % 26);
      } else if (char >= 97 && char <= 122) {
        // Lowercase letters
        return 97 +
            ((char - 97 + key.codeUnitAt(index % key.length) - 97) % 26);
      } else {
        return char; // Non-alphabetic characters remain unchanged
      }
    }));
  }

  /// Decrypts the ciphertext using the Vigenère cipher with the given key.
  String decrypt({required String cipherText, required String key}) {
    key = key.toLowerCase();
    return String.fromCharCodes(cipherText.codeUnits.mapIndexed((index, char) {
      if (char >= 65 && char <= 90) {
        // Uppercase letters
        return 65 +
            ((char - 65 - (key.codeUnitAt(index % key.length) - 97) + 26) % 26);
      } else if (char >= 97 && char <= 122) {
        // Lowercase letters
        return 97 +
            ((char - 97 - (key.codeUnitAt(index % key.length) - 97) + 26) % 26);
      } else {
        return char; // Non-alphabetic characters remain unchanged
      }
    }));
  }
}
