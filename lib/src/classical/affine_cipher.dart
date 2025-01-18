import 'package:dash_crypt/src/utils/sanitized.dart';

class AffineCipher {
  /// Encrypts the given plaintext using the Affine Cipher formula.
  String encrypt({required String plainText, required int a, required int b}) {
    _validateAffineKey(a);
    final m = 26; // Size of the alphabet
    final sanitized = _sanitizeAndTrackSpecials(plainText);

    final encryptedText = String.fromCharCodes(
      sanitized.text.codeUnits.map((char) {
        final base = _isUpperCase(char) ? 'A'.codeUnitAt(0) : 'a'.codeUnitAt(0);
        final x = char - base;
        final encrypted = (a * x + b) % m;
        return encrypted + base;
      }),
    );

    return _restoreSpecialCharacters(
      originalText: plainText,
      processedText: encryptedText,
      specialPositions: sanitized.positions,
    );
  }

  /// Decrypts the given ciphertext using the Affine Cipher formula.
  String decrypt({required String cipherText, required int a, required int b}) {
    _validateAffineKey(a);
    final m = 26; // Size of the alphabet
    final aInv = _modularInverse(a, m); // Modular multiplicative inverse of `a`
    final sanitized = _sanitizeAndTrackSpecials(cipherText);

    final decryptedText = String.fromCharCodes(
      sanitized.text.codeUnits.map((char) {
        final base = _isUpperCase(char) ? 'A'.codeUnitAt(0) : 'a'.codeUnitAt(0);
        final y = char - base;
        final decrypted =
            (aInv * (y - b) % m + m) % m; // Ensure positive modulo
        return decrypted + base;
      }),
    );

    return _restoreSpecialCharacters(
      originalText: cipherText,
      processedText: decryptedText,
      specialPositions: sanitized.positions,
    );
  }

  /// Checks if the given character is an uppercase letter.
  bool _isUpperCase(int char) {
    return char >= 'A'.codeUnitAt(0) && char <= 'Z'.codeUnitAt(0);
  }

  /// Validates that `a` and the size of the alphabet (26) are coprime.
  static void _validateAffineKey(int a) {
    if (_gcd(a, 26) != 1) {
      throw ArgumentError('The key "a" must be coprime with 26.');
    }
  }

  static int _gcd(int a, int b) {
    while (b != 0) {
      final temp = b;
      b = a % b;
      a = temp;
    }
    return a.abs();
  }

  static int _modularInverse(int a, int m) {
    for (var i = 1; i < m; i++) {
      if ((a * i) % m == 1) return i;
    }
    throw ArgumentError('No modular inverse exists for a = $a and m = $m.');
  }

  /// Sanitizes the input text and tracks positions of special characters.
  static SanitizedText _sanitizeAndTrackSpecials(String text) {
    final sanitized = StringBuffer();
    final positions = <int, String>{};
    for (var i = 0; i < text.length; i++) {
      final char = text[i];
      if (RegExp(r'[A-Za-z]').hasMatch(char)) {
        sanitized.write(char);
      } else {
        positions[i] = char; // Store non-alphabetic characters and positions
      }
    }
    return SanitizedText(sanitized.toString(), positions);
  }

  /// Restores special characters to their original positions.
  static String _restoreSpecialCharacters({
    required String originalText,
    required String processedText,
    required Map<int, String> specialPositions,
  }) {
    final buffer = StringBuffer();
    var index = 0;

    for (var i = 0; i < originalText.length; i++) {
      if (specialPositions.containsKey(i)) {
        buffer.write(specialPositions[i]);
      } else {
        buffer.write(processedText[index]);
        index++;
      }
    }

    return buffer.toString();
  }
}
