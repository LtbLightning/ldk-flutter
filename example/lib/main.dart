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
  final _ldkRust = LdkFlutter();

  @override
  void initState() {
    super.initState();
    getLdk();
  }

  openChannel() async{
    await _ldkRust.openChannel(
        peerPubKey: "03aa32db8e7b1f4012b3a994d55abecb57ddeb634e7d4fde1fd32d2447ca86d1cb",
        port: 9838,
        host: "127.0.0.1",
        amountInSats: 100000,
        isPublic: false);
  }
  listChannels() async{
    final res =  await _ldkRust.getAllChannels();
    for (var e in res){
      print( e.peerPubkey);
    }
  }
  getLdk() async{
    final dir = await getDocDir();
    await _ldkRust.ldkInit(
        host: "127.0.0.1",
        port: 18443,
        username: "polaruser",
        password: "polarpass",
        network:Network.REGTEST,
        path:dir);
  }
 Future<String> getDocDir() async{
    final res = await _ldkRust.getAppDocDirPath();
    print(res);
    return res;
  }
  getNodeInfo() async{
    final res = await _ldkRust.getNodeInfo();
    print("Local Balance ${res.localBalanceMsat}");
    print("Node PubKey ${res.nodePubKey}");
    print("No:of channels ${res.numUsableChannels}");
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
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TextButton(onPressed: (){
                getDocDir();
              }, child: Text("Get Doc Dir")),
              TextButton(onPressed: (){
                openChannel();
              }, child: Text("Open Channel")),
              TextButton(onPressed: (){
                listChannels();
              }, child: Text("List Channels")),
              TextButton(onPressed: (){
                getNodeInfo();
              }, child: Text("Get Node Info"))
            ],
          ),
        ),
      ),
    );
  }
}
