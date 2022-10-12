import 'package:flutter/material.dart';
import 'package:ldk_flutter/ldk_flutter.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _rustIsolatePlugin = LdkFlutter();

  @override
  void initState() {
    super.initState();
    getLdk();
  }
  getLdk() async{
   await _rustIsolatePlugin.ldkInit(
       host: "127.0.0.1",
        port: 18443,
        username: "polaruser",
        password: "polarpass",
        network:Network.REGTEST,
        path:"~/Library/Developer/CoreSimulator/Devices/8AFA2EBF-F65B-446A-B731-FF811EEFD54D/data/Containers/Data/Application/9A7D9E46-E4FA-4A2D-A68F-998612BC5A7C/Documents");
  }
  getDocDir() async{
    final res = await _rustIsolatePlugin.getAppDocDirPath();
    print(res);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('LDK Node'),
        ),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              ElevatedButton(onPressed: (){
                getDocDir();
              }, child: Text("Get Doc Dir"))
            ],
          ),
        ),
      ),
    );
  }
}
