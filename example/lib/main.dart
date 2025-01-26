import 'package:dash_crypt/dash_crypt.dart';
import 'package:flutter/material.dart';

void runEncryptionTestForAES({
  required AesMode algorithmName,
  required KeySize keySize,
  required String text,
  required String key,
  String? iv, // Optional for algorithms like ECB
}) async {
  try {


    final encryptor = _getEncryptorForAES(algorithmName, keySize);
    var ciphertext,decryptedText;
    if(algorithmName == AesMode.ecb){

      // Encrypt
       ciphertext =  encryptor.encrypt(
        text: text,
        key: key,
      );
    }else if (algorithmName == AesMode.gcm){
      ciphertext =  await encryptor.encrypt(
        text: text,
        key: key,
        iv: iv ?? ''
      );
    }
    else {
      // Encrypt
       ciphertext = encryptor.encrypt(
        text: text,
        key: key,
        iv: iv ?? '', // Use empty IV if not required
      );
    }


    if(algorithmName == AesMode.ecb){

      // Encrypt
       decryptedText =  encryptor.decrypt(
        text: ciphertext,
        key: key,
      );

    }else if (algorithmName == AesMode.gcm){
      // Decrypt
      decryptedText = await encryptor.decrypt(
        text: ciphertext,
        key: key,
        iv: iv ?? '', // Use empty IV if not required
      );
    } else {
      // Decrypt
       decryptedText = encryptor.decrypt(
        text: ciphertext,
        key: key,
        iv: iv ?? '', // Use empty IV if not required
      );
      }
    print('--- Testing $algorithmName with KeySize: ${keySize.name} ---');
    print('Ciphertext (Base64): $ciphertext');
    print('Decrypted Text: $decryptedText');


    isPassed(decryptedText,text);

  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}

dynamic _getEncryptorForAES(AesMode algorithmName, KeySize keySize) {
  switch (algorithmName) {
    case AesMode.cbc:
      return DashCrypt.AES__CBC(keySize: keySize);
    case AesMode.cfb:
      return DashCrypt.AES__CFB(keySize: keySize);
    case AesMode.ecb:
      return DashCrypt.AES__ECB(keySize: keySize);
    case AesMode.gcm:
      return DashCrypt.AES__GCM(keySize: keySize);
  // Add new algorithms here as you implement them
    default:
      throw ArgumentError('Unknown algorithm: $algorithmName');
  }
}
void isPassed(decryptedText,text){
  if (decryptedText == text) {
    print('✅ Test Passed!\n');
  } else {
    print('❌ Test Failed: Decrypted text does not match the original.\n');
  }
}


/// Add utils to generate key and iv
void main() {
  // CBC Tests
  runEncryptionTestForAES(
    algorithmName: AesMode.cbc,
    keySize: KeySize.aes128,
    text: 'Hello, AES-CBC!',
    key: '0123456789abcdef',
    iv: 'fedcba9876543210',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.cbc,
    keySize: KeySize.aes256,
    text: 'This is a longer text for testing AES CBC encryption and decryption.',
    key: '0123456789abcdef0123456789abcdef',
    iv: 'abcdef0123456789',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.cbc,
    keySize: KeySize.aes192,
    text: '1234567890abcdef',
    key: '0123456789abcdef01234567',
    iv: 'abcdefabcdef1234',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.cbc,
    keySize: KeySize.aes128,
    text: '12345',
    key: '0123456789abcdef',
    iv: 'fedcba9876543210',
  );

  // CFB Tests
  runEncryptionTestForAES(
    algorithmName: AesMode.cfb,
    keySize: KeySize.aes128,
    text: 'Hello, CFB!',
    key: '0123456789abcdef',
    iv: 'fedcba9876543210',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.cfb,
    keySize: KeySize.aes192,
    text: 'AES CFB 192-bit test.',
    key: '0123456789abcdef01234567',
    iv: 'abcdefabcdef1234',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.cfb,
    keySize: KeySize.aes256,
    text: 'This is a longer text for AES CFB mode testing.',
    key: '0123456789abcdef0123456789abcdef',
    iv: 'abcdef0123456789',
  );

  // ECB Tests
  runEncryptionTestForAES(
    algorithmName: AesMode.ecb,
    keySize: KeySize.aes128,
    text: 'Eighteen chars.!!',
    key: '0123456789abcdef',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.ecb,
    keySize: KeySize.aes192,
    text: 'Eighteen chars.!!',
    key: '0123456789abcdef01234567',
  );

  runEncryptionTestForAES(
    algorithmName: AesMode.ecb,
    keySize: KeySize.aes256,
    text: 'Eighteen chars.!!',
    key: '0123456789abcdef0123456789abcdef',
  );


  // Test AES-GCM 128-bit key
  runEncryptionTestForAES(
    algorithmName: AesMode.gcm,
    keySize: KeySize.aes128,
    text: 'Hello, AES-GCM!',
    key: '0123456789abcdef',
    iv: 'fedcba987654', // 12-byte IV required for GCM
  );

  // Test AES-GCM 192-bit key
  runEncryptionTestForAES(
    algorithmName: AesMode.gcm,
    keySize: KeySize.aes192,
    text: 'This is a GCM 192-bit test.',
    key: '0123456789abcdef01234567',
    iv: 'abcdef012345', // 12-byte IV
  );

  // Test AES-GCM 256-bit key
  runEncryptionTestForAES(
    algorithmName: AesMode.gcm,
    keySize: KeySize.aes256,
    text: 'This is a longer text for AES GCM mode testing.',
    key: '0123456789abcdef0123456789abcdef',
    iv: 'abcdefabcdef', // 12-byte IV
  );


  testAffine();
  testCaeser();
  testColumnar();
  testMonoalphabetic();
  testPlayfair();
  testRailFence();
  testVigenere();

  print('ecb generated IV : ${DashCrypt.generateIV(AesMode.ecb)}');
  print('cbc generated IV : ${DashCrypt.generateIV(AesMode.cbc)}');
  print('gcm generated IV : ${DashCrypt.generateIV(AesMode.gcm)}');
  print('cfb generated IV : ${DashCrypt.generateIV(AesMode.cfb)}');
  print('aes128 generated Key : ${DashCrypt.generateKey(KeySize.aes128)}');
  print('aes192 generated Key : ${DashCrypt.generateKey(KeySize.aes192)}');
  print('aes256 generated Key : ${DashCrypt.generateKey(KeySize.aes256)}');

  runApp(const MyApp());
}


void testCaeser(){
  try{
    var p1= "HELLOCAESAR";
    var shift = 3;
    var caesar = DashCrypt.Caesar.encrypt(text: p1, shift:shift );
    var caesarDec = DashCrypt.Caesar.decrypt(text: caesar, shift:shift );
    print('--- Testing Caesar with Shift: ${shift}  ---');
    print('Ciphertext (Base64): $caesar');
    print('Decrypted Text: $caesarDec');
    isPassed(caesarDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}
void testColumnar(){
  try{
    var p1= "HELLOCOLUMNAR";
    var key = 3;
    var columnar = DashCrypt.ColumnarTransposition.encrypt(text: p1, numberOfColumns:key );
    var columnarDec = DashCrypt.ColumnarTransposition.decrypt(text: columnar, numberOfColumns:key );
    print('--- Testing Columnar with Key: ${key}  ---');
    print('Ciphertext (Base64): $columnar');
    print('Decrypted Text: $columnarDec');
    isPassed(columnarDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}
void testMonoalphabetic(){
  try{
    var p1= "HELLOMONO";
    var key = "QWERTYUIOPLKJHGFDSAZXCVBNM";
    var monoalphabetic = DashCrypt.Monoalphabetic.encrypt(text: p1, key:key );
    var monoalphabeticDec = DashCrypt.Monoalphabetic.decrypt(text: monoalphabetic, key:key );
    print('--- Testing Monoalphabetic with Key: ${key}  ---');
    print('Ciphertext (Base64): $monoalphabetic');
    print('Decrypted Text: $monoalphabeticDec');
    isPassed(monoalphabeticDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}
void testPlayfair(){
  try{
    var p1= "HELLOPLAYFAIR";
    var key = "KEYWORD";
    var playfair = DashCrypt.Playfair.encrypt(text: p1, key:key );
    var playfairDec = DashCrypt.Playfair.decrypt(text: playfair, key:key );
    print('--- Testing PlayFair with Key: ${key}  ---');
    print('Ciphertext (Base64): $playfair');
    print('Decrypted Text: $playfairDec');
    isPassed(playfairDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}

void testRailFence(){
  try{
    var p1= "HELLORAILFENCE";
    var key = 3;
    var railFence = DashCrypt.RailFence.encrypt(text: p1, numberOfRails:key );
    var railFenceDec = DashCrypt.RailFence.decrypt(text: railFence, numberOfRails:key );
    print('--- Testing RailFence with Key: ${key}  ---');
    print('Ciphertext (Base64): $railFence');
    print('Decrypted Text: $railFenceDec');
    isPassed(railFenceDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}

void testVigenere(){
  try{
    var p1= "HELLOVIGENERE";
    var key = 'KEY';
    var vigenere = DashCrypt.Vigenere.encrypt(text: p1, key:key );
    var vigenereDec = DashCrypt.Vigenere.decrypt(text: vigenere, key:key );
    print('--- Testing Vigenere with Key: ${key}  ---');
    print('Ciphertext (Base64): $vigenere');
    print('Decrypted Text: $vigenereDec');
    isPassed(vigenereDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}

void testAffine(){
  try{
    var p1= "HELLOVIGENERE";
    var a = 5;
    var b = 8;
    var affine = DashCrypt.Affine.encrypt(text: p1, a:a , b:b );
    var affineDec = DashCrypt.Affine.decrypt(text: affine, a:a , b:b  );
    print('--- Testing Affine with A: ${a} and B: ${b} ---');
    print('Ciphertext (Base64): $affine');
    print('Decrypted Text: $affineDec');
    isPassed(affineDec,p1);
  } catch (e) {
    print('❌ Error during test: $e\n');
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // TRY THIS: Try running your application with "flutter run". You'll see
        // the application has a purple toolbar. Then, without quitting the app,
        // try changing the seedColor in the colorScheme below to Colors.green
        // and then invoke "hot reload" (save your changes or press the "hot
        // reload" button in a Flutter-supported IDE, or press "r" if you used
        // the command line to start the app).
        //
        // Notice that the counter didn't reset back to zero; the application
        // state is not lost during the reload. To reset the state, use hot
        // restart instead.
        //
        // This works for code too, not just values: Most code changes can be
        // tested with just a hot reload.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // TRY THIS: Try changing the color here to a specific color (to
        // Colors.amber, perhaps?) and trigger a hot reload to see the AppBar
        // change color while the other colors stay the same.
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          //
          // TRY THIS: Invoke "debug painting" (choose the "Toggle Debug Paint"
          // action in the IDE, or press "p" in the console), to see the
          // wireframe for each widget.
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
