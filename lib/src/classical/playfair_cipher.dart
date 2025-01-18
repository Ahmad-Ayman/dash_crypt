class PlayfairCipher {
  late List<List<String>> keySquare;

  PlayfairCipher();

  List<List<String>> _createKeySquare(String key) {
    const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 'J' is excluded
    final keySet = <String>{};
    final processedKey = key.toUpperCase().replaceAll("J", "I");

    // Create a list of unique characters from the key and alphabet
    final combined = (processedKey + alphabet)
        .split("")
        .where((char) => keySet.add(char))
        .toList();

    // Build 5x5 key square
    return List.generate(5, (i) => combined.sublist(i * 5, (i + 1) * 5));
  }

  void _initializeKeySquare(String key) {
    keySquare = _createKeySquare(key);
  }

  String _prepareText(String text, {bool forEncryption = true}) {
    text = text
        .toUpperCase()
        .replaceAll(RegExp(r"[^A-Z]"), "")
        .replaceAll("J", "I");

    if (forEncryption) {
      final buffer = StringBuffer();
      for (int i = 0; i < text.length; i++) {
        final current = text[i];
        final next = i + 1 < text.length ? text[i + 1] : null;

        buffer.write(current);
        if (next != null && current == next) {
          buffer.write("X");
        }
      }
      if (buffer.length % 2 != 0) {
        buffer.write("X"); // Add padding if odd length
      }
      return buffer.toString();
    }

    return text;
  }

  List<int> _findPosition(String letter) {
    for (int row = 0; row < 5; row++) {
      for (int col = 0; col < 5; col++) {
        if (keySquare[row][col] == letter) {
          return [row, col];
        }
      }
    }
    throw ArgumentError("Letter not found in key square");
  }

  String encrypt({required String plainText, required String key}) {
    _initializeKeySquare(key);
    plainText = _prepareText(plainText);
    final buffer = StringBuffer();

    for (int i = 0; i < plainText.length; i += 2) {
      final digraph = plainText.substring(i, i + 2);
      final pos1 = _findPosition(digraph[0]);
      final pos2 = _findPosition(digraph[1]);

      if (pos1[0] == pos2[0]) {
        // Same row
        buffer.write(keySquare[pos1[0]][(pos1[1] + 1) % 5]);
        buffer.write(keySquare[pos2[0]][(pos2[1] + 1) % 5]);
      } else if (pos1[1] == pos2[1]) {
        // Same column
        buffer.write(keySquare[(pos1[0] + 1) % 5][pos1[1]]);
        buffer.write(keySquare[(pos2[0] + 1) % 5][pos2[1]]);
      } else {
        // Rectangle swap
        buffer.write(keySquare[pos1[0]][pos2[1]]);
        buffer.write(keySquare[pos2[0]][pos1[1]]);
      }
    }

    return buffer.toString();
  }

  String decrypt({required String cipherText, required String key}) {
    _initializeKeySquare(key);
    final buffer = StringBuffer();

    for (int i = 0; i < cipherText.length; i += 2) {
      final digraph = cipherText.substring(i, i + 2);
      final pos1 = _findPosition(digraph[0]);
      final pos2 = _findPosition(digraph[1]);

      if (pos1[0] == pos2[0]) {
        // Same row
        buffer.write(keySquare[pos1[0]][(pos1[1] - 1 + 5) % 5]);
        buffer.write(keySquare[pos2[0]][(pos2[1] - 1 + 5) % 5]);
      } else if (pos1[1] == pos2[1]) {
        // Same column
        buffer.write(keySquare[(pos1[0] - 1 + 5) % 5][pos1[1]]);
        buffer.write(keySquare[(pos2[0] - 1 + 5) % 5][pos2[1]]);
      } else {
        // Rectangle swap
        buffer.write(keySquare[pos1[0]][pos2[1]]);
        buffer.write(keySquare[pos2[0]][pos1[1]]);
      }
    }

    return buffer.toString();
  }
}
