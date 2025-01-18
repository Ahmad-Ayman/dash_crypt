/// Implements the Monoalphabetic Substitution Cipher encryption and decryption.
class MonoalphabeticCipher {
  /// Encrypts the plaintext using a custom key mapping.
  String encrypt({required String plainText, required String key}) {
    assert(key.length == 26,
        'Key must be 26 characters long, representing a mapping for the entire alphabet.');

    const upperAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowerAlphabet = 'abcdefghijklmnopqrstuvwxyz';

    // Generate encryption map for both uppercase and lowercase
    final Map<String, String> upperKeyMap = {
      for (int i = 0; i < upperAlphabet.length; i++) upperAlphabet[i]: key[i]
    };
    final Map<String, String> lowerKeyMap = {
      for (int i = 0; i < lowerAlphabet.length; i++)
        lowerAlphabet[i]: key[i].toLowerCase()
    };

    // Merge the two maps
    final Map<String, String> keyMap = {}
      ..addAll(upperKeyMap)
      ..addAll(lowerKeyMap);

    // Encrypt the text
    final encrypted = plainText.split('').map((char) {
      return keyMap[char] ?? char; // Keep non-alphabetic characters unchanged
    }).join();

    assert(encrypted.isNotEmpty, 'Encryption resulted in an empty ciphertext.');
    return encrypted;
  }

  /// Decrypts the ciphertext using a custom key mapping.
  String decrypt({required String cipherText, required String key}) {
    assert(key.length == 26,
        'Key must be 26 characters long, representing a mapping for the entire alphabet.');

    const upperAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowerAlphabet = 'abcdefghijklmnopqrstuvwxyz';

    // Generate decryption map for both uppercase and lowercase
    final Map<String, String> upperInverseKeyMap = {
      for (int i = 0; i < upperAlphabet.length; i++) key[i]: upperAlphabet[i]
    };
    final Map<String, String> lowerInverseKeyMap = {
      for (int i = 0; i < lowerAlphabet.length; i++)
        key[i].toLowerCase(): lowerAlphabet[i]
    };

    // Merge the two maps
    final Map<String, String> inverseKeyMap = {}
      ..addAll(upperInverseKeyMap)
      ..addAll(lowerInverseKeyMap);

    // Decrypt the text
    final decrypted = cipherText.split('').map((char) {
      return inverseKeyMap[char] ??
          char; // Keep non-alphabetic characters unchanged
    }).join();

    assert(decrypted.isNotEmpty, 'Decryption resulted in an empty plaintext.');
    return decrypted;
  }
}
