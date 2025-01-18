class RailFenceCipher {
  String encrypt({required String plainText, required int numberOfRails}) {
    final rails = List.generate(numberOfRails, (_) => StringBuffer());
    int direction = 1, railIndex = 0;

    for (final char in plainText.runes) {
      rails[railIndex].write(String.fromCharCode(char));
      railIndex += direction;
      if (railIndex == 0 || railIndex == numberOfRails - 1) direction *= -1;
    }

    return rails.join();
  }

  String decrypt({required String cipherText, required int numberOfRails}) {
    final pattern = List.generate(cipherText.length, (_) => 0);
    int direction = 1, railIndex = 0;

    for (int i = 0; i < cipherText.length; i++) {
      pattern[i] = railIndex;
      railIndex += direction;
      if (railIndex == 0 || railIndex == numberOfRails - 1) direction *= -1;
    }

    final rails = List.generate(numberOfRails, (_) => []);
    final railLengths = List.filled(numberOfRails, 0);

    for (var i in pattern) {
      railLengths[i]++;
    }

    int charIndex = 0;
    for (int i = 0; i < numberOfRails; i++) {
      rails[i] =
          cipherText.substring(charIndex, charIndex + railLengths[i]).split('');
      charIndex += railLengths[i];
    }

    final decrypted = StringBuffer();
    for (var i in pattern) {
      decrypted.write(rails[i].removeAt(0));
    }

    return decrypted.toString();
  }
}
