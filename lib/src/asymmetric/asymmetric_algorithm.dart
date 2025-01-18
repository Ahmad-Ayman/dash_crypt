import '../encryption_algorithm.dart';


/// Interface for asymmetric encryption algorithms.
abstract class AsymmetricAlgorithm extends EncryptionAlgorithm {
  /// Generates a key pair (public and private keys).
  Map<String, String> generateKeyPair();
}
