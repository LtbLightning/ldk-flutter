import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/src/utils/exceptions.dart';
import 'package:path_provider/path_provider.dart';
class LdkFlutter {
  Future<String> getAppDocDirPath() async {
    final Directory appDocDir = await getApplicationDocumentsDirectory();
    return appDocDir.path;
  }

 Future ldkInit({required String host,
    required int port,
   required int port2,
    required String username,
    required String password,
    required Network network,
   required String pubKey,
   required int amount,
    String? path}) async {
    final ReceivePort receivePort= ReceivePort();
    final Map<String, dynamic> args = {
      "host": host,
      "port": port,
      "port2": port2,
      "username": username,
      "password": password,
      "network": network,
      "path": path,
      "pubKey": pubKey,
      "amount": amount,
      "isolatePort": receivePort.sendPort,
    };
   await Isolate.spawn(_ldkInit, args);
    receivePort.listen(( message) {
     print('Ldk Node Successfully Created \nNode Id: $message');
    });
  }

  Future _ldkInit( Map<String, dynamic>  node) async {
    print("Creating node..");
    final res = await  loaderApi.startLdkAndOpenChannel(
        host: node['host'],
        port: node['port'],
        username: node['username'],
        password: node['password'],
        nodeNetwork:node['network'] as Network,
        path: node['path'],
        pubKey: node['pubKey'],
        port2:node['port2'],
        amount: node['amount'] as int,
    );
    final isolatePort = node['isolatePort'] as SendPort;
    Isolate.exit(isolatePort, res);
  }

  Future <String>  openChannel({required String peerPubKey, required int port, required String host, required int amountInSats, required bool isPublic})async{
    final channels = await getAllChannels();
    for(var e  in channels){
      if(e.peerPubkey == peerPubKey ){
        throw ChannelException(message: "Multiple channels unsupported: Already connected to peer $peerPubKey");
      }
    }
    final peerAddStr = "$host:$port";
    final res = await  loaderApi.openChannel(
      pubKeyStr: peerPubKey,
      peerAddStr: peerAddStr,
      amount: amountInSats,
      isPublic: isPublic,
    );
    return res ;
  }


  Future<LdkNodeInfo> getNodeInfo() async {
    final res = await loaderApi.getNodeInfo();
    return res;
  }
  Future<List<ChannelInfo>> getAllChannels() async {
    final res = await loaderApi.listChannels();
    return res;
  }

  Future<List<String>> getAllPeer() async {
    final res = await loaderApi.listPeers();
    return res;
  }
  closeChannel(String channelId, String peerPubKey) async {
    final res = await loaderApi.closeChannel(channelIdStr: channelId, peerPubkeyStr: peerPubKey);
    return res;
  }
  forceCloseChannel(String channelId, String peerPubKey) async {
    final res = await loaderApi.closeChannel(channelIdStr: channelId, peerPubkeyStr: peerPubKey);
    return res;
  }

}
