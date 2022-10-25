import 'package:flutter/material.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'dart:io' show Platform;
void main() async {
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

  Future<String> getDocDir() async {
    final res = await _ldkRust.getAppDocDirPath();
    print(res);
    return res;
  }

  getLdk() async {
    final dir = await getDocDir();
    await _ldkRust.ldkInit(
        host: Platform.isAndroid? "10.0.2.2":"127.0.0.1",
        port: 18443,
        username: "polaruser",
        password: "polarpass",
        pubKey: "02636a5c5d92f05e93678f7da94d927789ea4e86ab29b7bf0be14ce09a52e8654f",
        port2: 9836,
        amount: 10000,
        network: Network.REGTEST,
        path: dir);
  }

  // openChannel() async {
  //  final res =  await _ldkRust.openChannel(
  //       peerPubKey: "02636a5c5d92f05e93678f7da94d927789ea4e86ab29b7bf0be14ce09a52e8654f",
  //       port: 9836,
  //      amountInSats: 10000,
  //       host: Platform.isAndroid? "10.0.2.2":"127.0.0.1",
  //
  //       isPublic: true);
  //  print(res);
  // }

  listChannels() async {
    final res = await _ldkRust.getAllChannels();
    for (var e in res) {
      print("Chanel Id ${e.channelId}");
      print("Balance ${e.localBalanceMsat}");
      print("Peer Pub Key ${e.peerPubkey}");
      print("Peer Alias ${e.peerAlias}");
      print("funding txid ${e.fundingTxid}");
      print("is ready  ${e.isChannelReady}");
      print("can send payments  ${e.channelCanSendPayments}");
      print("is public  ${e.public}");
    }
  }
 getPeers() async {
    final res = await _ldkRust.getAllPeer();
    res.forEach((element) {print(element);});
  }

  // closeChannel() async {
  //   final res = await _ldkRust.closeChannel(channelId, peerPubKey);
  //   res.forEach((element) {print(element);});
  // }

  getNodeInfo() async {
    final res = await _ldkRust.getNodeInfo();
    print("Local Balance ${res.localBalanceMsat}");
    print("Node Pub Key ${res.nodePubKey}");
    print("No:of channels ${res.numChannels}");
    print("No:of usable channels ${res.numUsableChannels}");
    print("No:of peers ${res.numPeers}");
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
              TextButton(
                  onPressed: () {
                    getDocDir();
                  },
                  child: Text("Get Doc Dir")),
              // TextButton(
              //     onPressed: () {
              //       openChannel();
              //     },
              //     child: Text("Open Channel")),
              TextButton(
                  onPressed: () {
                    listChannels();
                  },
                  child: Text("List Channels")),
              TextButton(
                  onPressed: () {
                    getPeers();
                  },
                  child: Text("List Peeers")),
              TextButton(
                  onPressed: () {
                    getNodeInfo();
                  },
                  child: Text("Get Node Info"))
            ],
          ),
        ),
      ),
    );
  }
}
