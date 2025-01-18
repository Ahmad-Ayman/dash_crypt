import 'dart:convert';
import 'dart:typed_data';
import 'aes_gcm.dart'; // Placeholder for GCM implementation
import 'aes_key_expansion.dart';
import 'aes_round_operations.dart';

/// Base class for AES mode strategies.
abstract class AESModeStrategy {
  String encrypt(String plaintext, Uint8List key, Uint8List iv);
  String decrypt(String ciphertext, Uint8List key, Uint8List iv);
}



