import 'package:dash_crypt/dash_crypt.dart';
import 'package:flutter/material.dart';

void main() {
  try {
    // Example plaintext
    Map jso = {
      "success": true,
      'error': ['test'],
      'data': {
        "name": "Ahmed",
        "age": 12,
        "courses": [
          {
            "map": {"ww": 12, "dada": false}
          }
        ]
      }
    };
    // var plainText = jsonEncode(jso);
    var plainText = 'Hello, Welcome Ahmed to Dash Crypt';

    // Test AES-128 with CBC mode
    // final key128 = DashCrypt.generateKey(128);
    final key128 = '''TurnDigital#1234''';
    // final iv128 = DashCrypt.generateIV(16);
    final iv128 = '123456789ABCDEFG';

    print('AES-128 - CBC');
    print('Plain text : $plainText');
    final encrypted128CBC = DashCrypt.AES128.encrypt(
      plainText: plainText,
      key: key128,
      iv: iv128,
      mode: AESMode.CBC,
    );
    print('Key: $key128');
    print("Encrypted: $encrypted128CBC");

    final decrypted128CBC = DashCrypt.AES128.decrypt(
      cipherText: encrypted128CBC,
      key: key128,
      iv: iv128,
      mode: AESMode.CBC,
    );
    print("Decrypted: $decrypted128CBC");
    print('#############################');
    final key192 = DashCrypt.generateKey(192);
    final iv192 = DashCrypt.generateIV(16);

    print('AES-192 - CBC');
    print('Plain text : $plainText');
    print('Key: $key192');
    final encrypted192CBC = DashCrypt.AES192.encrypt(
      plainText: plainText,
      key: key192,
      iv: iv192,
      mode: AESMode.CBC,
    );
    print("Encrypted: $encrypted192CBC");

    final decrypted192CBC = DashCrypt.AES192.decrypt(
      cipherText: encrypted192CBC,
      key: key192,
      iv: iv192,
      mode: AESMode.CBC,
    );
    print("Decrypted: $decrypted192CBC");
    print('#############################');
    final key256 = DashCrypt.generateKey(256);
    final iv256 = DashCrypt.generateIV(16);
    print('AES-256 - CBC');
    print('Plain text : $plainText');
    print('Key: $key256');
    final encrypted256CBC = DashCrypt.AES256.encrypt(
      plainText: plainText,
      key: key256,
      iv: iv256,
      mode: AESMode.CBC,
    );
    print("Encrypted: $encrypted256CBC");

    final decrypted256CBC = DashCrypt.AES256.decrypt(
      cipherText: encrypted256CBC,
      key: key256,
      iv: iv256,
      mode: AESMode.CBC,
    );
    print("Decrypted: $decrypted256CBC");

    print('#############################');
    print('#############################');
    print('AES-128 - GCM');

    final key128_1 = DashCrypt.generateKey(128);
    final ivGCM = DashCrypt.generateIV(12);
    print('Key: $key128_1');
    print('ivGCM: $ivGCM');
    final encrypted128GCM = DashCrypt.AES128.encrypt(
      plainText: plainText,
      key: key128_1,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Encrypted: $encrypted128GCM");

    final decrypted128GCM = DashCrypt.AES128.decrypt(
      cipherText: encrypted128GCM,
      key: key128_1,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Decrypted: $decrypted128GCM");
    print('#############################');
    print('AES-192 - GCM');
    final key1921 = DashCrypt.generateKey(192);
    print('Key: $key1921');
    final encrypted192GCM = DashCrypt.AES192.encrypt(
      plainText: plainText,
      key: key1921,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Encrypted: $encrypted192GCM");

    final decrypted192GCM = DashCrypt.AES192.decrypt(
      cipherText: encrypted192GCM,
      key: key1921,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Decrypted: $decrypted192GCM");
    print('#############################');
    print('AES-256 - GCM');
    final key2561 = "TurnDigital#1234TurnDigital#1234";
    print('Key: $key2561');
    final encrypted256GCM = DashCrypt.AES256.encrypt(
      plainText: plainText,
      key: key2561,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Encrypted: $encrypted256GCM");

    final decrypted256GCM = DashCrypt.AES256.decrypt(
      cipherText: encrypted256GCM,
      key: key2561,
      iv: ivGCM,
      mode: AESMode.GCM,
    );
    print("Decrypted: $decrypted256GCM");
    print('#############################');
    print('#############################');
    print('AES-128 - ECB');
    final key128_2 = DashCrypt.generateKey(128);
    print('Key: $key128_2');
    final encrypted128ECB = DashCrypt.AES128.encrypt(
      plainText: plainText,
      key: key128_2,
      mode: AESMode.ECB,
    );
    print("Encrypted: $encrypted128ECB");

    final decrypted128ECB = DashCrypt.AES128.decrypt(
      cipherText: encrypted128ECB,
      key: key128_2,
      mode: AESMode.ECB,
    );
    print("Decrypted: $decrypted128ECB");
    print('#############################');
    print('AES-192 - ECB');
    final key1922 = DashCrypt.generateKey(192);
    print('Key: $key1922');
    final encrypted192ECB = DashCrypt.AES192.encrypt(
      plainText: plainText,
      key: key1922,
      mode: AESMode.ECB,
    );
    print("Encrypted: $encrypted192ECB");

    final decrypted192ECB = DashCrypt.AES192.decrypt(
      cipherText: encrypted192ECB,
      key: key1922,
      mode: AESMode.ECB,
    );
    print("Decrypted: $decrypted192ECB");
    print('#############################');
    print('AES-256 - ECB');
    final key2563 = "TurnDigital#1234TurnDigital#1234";
    print('key : $key2563');
    final encrypted256ECB = DashCrypt.AES256.encrypt(
      plainText: plainText,
      key: key2563,
      mode: AESMode.ECB,
    );
    print("Encrypted: $encrypted256ECB");

    final decrypted256ECB = DashCrypt.AES256.decrypt(
      cipherText: encrypted256ECB,
      key: key2563,
      mode: AESMode.ECB,
    );
    print("Decrypted: $decrypted256ECB");

    print('#############################');
    print('#############################');
    print('Caesar Cipher');
    final encryptedCaesar = DashCrypt.Caesar.encrypt(
      plainText: plainText,
      shift: 3,
    );
    print("Caesar Encrypted: $encryptedCaesar");

    final decryptedCaesar = DashCrypt.Caesar.decrypt(
      cipherText: encryptedCaesar,
      shift: 3,
    );
    print("Caesar Decrypted: $decryptedCaesar");
    print('#############################');
    print('#############################');
    print('Vigenere Cipher');
    final encryptedVigenere = DashCrypt.Vigenere.encrypt(
      plainText: plainText,
      key: "KEY",
    );
    print("Vigenere Encrypted: $encryptedVigenere");

    final decryptedVigenere = DashCrypt.Vigenere.decrypt(
      cipherText: encryptedVigenere,
      key: "KEY",
    );
    print("Vigenere Decrypted: $decryptedVigenere");

    print('#############################');
    print('#############################');
    print('Playfair Cipher');
    final encryptedPlayfair = DashCrypt.Playfair.encrypt(
      plainText: plainText,
      key: "HELLO",
    );
    print("Playfair Encrypted: $encryptedPlayfair");

    final decryptedPlayfair = DashCrypt.Playfair.decrypt(
      cipherText: encryptedPlayfair,
      key: "HELLO",
    );
    print("Playfair Decrypted: $decryptedPlayfair");

    print('#############################');
    print('#############################');
    print('Rail Fence Cipher');

    final encryptedRailFence = DashCrypt.RailFence.encrypt(
      plainText: plainText,
      numberOfRails: 3,
    );
    print("Rail Fence Encrypted: $encryptedRailFence");

    final decryptedRailFence = DashCrypt.RailFence.decrypt(
      cipherText: encryptedRailFence,
      numberOfRails: 3,
    );
    print("Rail Fence Decrypted: $decryptedRailFence");

    print('#############################');
    print('#############################');
    print('Affine Cipher');
    final encryptedAffine = DashCrypt.Affine.encrypt(
      plainText: plainText,
      a: 5,
      b: 8,
    );
    print("Affine Encrypted: $encryptedAffine");

    final decryptedAffine = DashCrypt.Affine.decrypt(
      cipherText: encryptedAffine,
      a: 5,
      b: 8,
    );
    print("Affine Decrypted: $decryptedAffine");

    print('#############################');
    print('#############################');
    print('Monoalphabetic Cipher');
    const keyMono = "QWERTYUIOPASDFGHJKLZXCVBNM";
    final encryptedMono = DashCrypt.Monoalphabetic.encrypt(
      plainText: plainText,
      key: keyMono,
    );
    print("keyMono Encrypted: $encryptedMono");

    final decryptedMono = DashCrypt.Monoalphabetic.decrypt(
      cipherText: encryptedMono,
      key: keyMono,
    );
    print("keyMono Decrypted: $decryptedMono");
    print('#############################');
    print('#############################');
    print('Columnar Transposition Cipher');
    const keyTrans = 3;
    final encryptedColumnar = DashCrypt.ColumnarTransposition.encrypt(
      plainText: plainText,
      key: keyTrans,
    );
    print("Columnar Transposition Encrypted: $encryptedColumnar");

    final decryptedColumnar = DashCrypt.ColumnarTransposition.decrypt(
      cipherText: encryptedColumnar,
      key: keyTrans,
    );
    print("Columnar Transposition Decrypted: $decryptedColumnar");
  } catch (e, stackTrace) {
    print("Error: $e\n$stackTrace");
  }
  runApp(const MyApp());
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
