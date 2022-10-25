import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/src/utils/exceptions.dart';
import 'package:path_provider/path_provider.dart';
class LdkFlutter {
  Future<String> getDirPath(DirectoryType directoryType) async {
    switch(directoryType){
      case DirectoryType.ApplicationDocumentsDirectory:
        final Directory appDocDir = await getApplicationDocumentsDirectory();
        return appDocDir.path;
      case DirectoryType.ApplicationSupportDirectory:
        final Directory appDocDir = await getApplicationSupportDirectory();
        return appDocDir.path;
    }
  }

  Future ldkInit({required String host,
    required int port,
    required String username,
    required String password,
    required Network network,
    required String path}) async {
    final ReceivePort receivePort= ReceivePort();
    final Map<String, dynamic> args = {
      "host": host,
      "port": port,
      "username": username,
      "password": password,
      "network": network,
      "path": path,
      "isolatePort": receivePort.sendPort,
    };
    await Isolate.spawn(_ldkInit, args);
    receivePort.listen(( message) {
      print('Ldk Node Successfully Created \nNode Id: $message');
    });
  }

  Future _ldkInit( Map<String, dynamic>  node) async {
    print("Creating node..");
    final res = await  loaderApi.startLdk(
      host: node['host'],
      port: node['port'],
      username: node['username'],
      password: node['password'],
      nodeNetwork:node['network'] as Network,
      path: node['path'],
    );
    final isolatePort = node['isolatePort'] as SendPort;
    Isolate.exit(isolatePort, res);
  }

  Future<LdkNodeInfo> getNodeInfo() async {
    final res = await loaderApi.getNodeInfo();
    return res;
  }

  Future <String>  connectPeer({required String peerPubKey, required int port, required String host})async{
    final channels = await listChannels();
    for(var e  in channels){
      if(e.peerPubkey == peerPubKey ){
        throw ChannelException(message: "Multiple channels unsupported: Already connected to peer $peerPubKey");
      }
    }
    final peerAddStr = "$host:$port";
    final res = await  loaderApi.connectPeer(
      pubKeyStr: peerPubKey,
      peerAddStr: peerAddStr,
    );
    return res;
  }

  Future<List<String>> listPeers() async {
    final res = await loaderApi.listPeers();
    return res;
  }

  Future <String>  openChannel({required String peerPubKey, required int port, required String host, required int amountInSats, required bool isPublic})async{
    final channels = await listChannels();
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

  Future<List<ChannelInfo>> listChannels() async {
    final res = await loaderApi.listChannels();
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
