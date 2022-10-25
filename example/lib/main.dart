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
  final ldkFlutter = LdkFlutter();

  @override
  void initState() {
    super.initState();
    startLdk();
  }

  Future<String> getDir() async {
    final res = await ldkFlutter
        .getDirPath(DirectoryType.ApplicationDocumentsDirectory);
    print(res);
    return res;
  }

  startLdk() async {
    final dir = await getDir();
    await ldkFlutter.ldkInit(
        host: Platform.isAndroid ? "10.0.2.2" : "127.0.0.1",
        port: 18443,
        username: "polaruser",
        password: "polarpass",
        network: Network.REGTEST,
        path: dir);
  }

  getNodeInfo() async {
    final res = await ldkFlutter.getNodeInfo();
    print("Local Balance ${res.localBalanceMsat}");
    print("Node Pub Key ${res.nodePubKey}");
    print("No:of channels ${res.numChannels}");
    print("No:of usable channels ${res.numUsableChannels}");
    print("No:of peers ${res.numPeers}");
  }

  // For testing replace the peerPubKey, port and host with your own
  connectPeer() async {
    final res = await ldkFlutter.connectPeer(
        peerPubKey:
            "02e837c5c65414be833a627043c44b69ec2061298b984323e512297f142c3fae3c",
        port: 9738,
        // Please change the following line to host: "127.0.0.1" if you are not using an emulator,
        host: Platform.isAndroid ? "10.0.2.2" : "127.0.0.1");
    print(res);
  }

  getPeers() async {
    final res = await ldkFlutter.listPeers();
    res.forEach((e) {
      print(e);
    });
  }

  openChannel() async {
    final res = await ldkFlutter.openChannel(
        peerPubKey:
            "02636a5c5d92f05e93678f7da94d927789ea4e86ab29b7bf0be14ce09a52e8654f",
        port: 9836,
        amountInSats: 10000,
        // Please change the following line to host: "127.0.0.1" if you are not using an emulator,
        host: Platform.isAndroid ? "10.0.2.2" : "127.0.0.1",
        isPublic: true);
    print(res);
  }

  listChannels() async {
    final res = await ldkFlutter.listChannels();
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

  closeChannel() async {
    //Replace channel id with yours
    await ldkFlutter.closeChannel(
        "f88a2f73032922f45c7724b75595de4a9113b99d0808ce62f600022d83922fe7",
        "02636a5c5d92f05e93678f7da94d927789ea4e86ab29b7bf0be14ce09a52e8654f");
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
                    getDir();
                  },
                  child: Text("Get Doc Dir")),
              TextButton(
                  onPressed: () {
                    getNodeInfo();
                  },
                  child: Text("Get Node Info")),
              TextButton(
                  onPressed: () {
                    connectPeer();
                  },
                  child: Text("Connect Peer")),
              TextButton(
                  onPressed: () {
                    getPeers();
                  },
                  child: Text("List Peers")),
              TextButton(
                  onPressed: () {
                    openChannel();
                  },
                  child: Text("Open Channel")),
              TextButton(
                  onPressed: () {
                    listChannels();
                  },
                  child: Text("List Channels")),
              TextButton(
                  onPressed: () {
                    closeChannel();
                  },
                  child: Text("Close Channel")),
            ],
          ),
        ),
      ),
    );
  }
}
