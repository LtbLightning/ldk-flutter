import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'package:isolate/ports.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/src/models/ldk_node.dart';
import 'package:path_provider/path_provider.dart';
class LdkFlutter {
  Future<String> getAppDocDirPath() async {
    final Directory _appDocDir = await getApplicationDocumentsDirectory();
    return _appDocDir.path;
  }

  Future<String> openChannel({required String pubKey, required int port, required String host, required int amountInSats, required bool isPublic})async{
    final peerAddStr = "$host:$port";
    final res = await loaderApi.openChannel(peerAddStr: peerAddStr,  isPublic: isPublic, amount: amountInSats, pubKeyStr: pubKey);
    print(res);
    return res;
  }

  ldkInit({required String host,
    required int port,
    required String username,
    required String password,
    required Network network,
    String? path}) async {
    final ReceivePort receivePort= ReceivePort();
    final args = LdkNode(
        host: host,
        port: port,
        username: username,
        password: password,
        network: network,
        path: path ?? "~/Library/Developer/CoreSimulator/Devices/8AFA2EBF-F65B-446A-B731-FF811EEFD54D/data/Containers/Data/Application/9A7D9E46-E4FA-4A2D-A68F-998612BC5A7C/Documents" ,
        isolatePort: receivePort.sendPort);
    await Isolate.spawn(_ldkInit, args);
    receivePort.listen((message) {
     print('Ldk Node Successfully Created \nNode Id: $message');
    });
  }

  _ldkInit( LdkNode node) async {
    print("Creating LDK Node......");
    final res = await  loaderApi.startLdk(
        host: node.host,
        port: node.port,
        username: node.username,
        password: node.password,
        nodeNetwork:node.network.name.toString(),
        path: node.path
    );
    node.isolatePort.send(res);
  }


  Future<String> getNodeId() async {
    return "";
  }
}
