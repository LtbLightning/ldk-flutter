import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'package:ldk_flutter/ldk_flutter.dart';
import 'package:ldk_flutter/src/utils/exceptions.dart';
import 'package:path_provider/path_provider.dart';
import 'models/ldk_node_args.dart';
class LdkFlutter {
  Future<String> getAppDocDirPath() async {
    final Directory _appDocDir = await getApplicationDocumentsDirectory();
    return _appDocDir.path;
  }

  ldkInit({required String host,
    required int port,
    required String username,
    required String password,
    required Network network,
    String? path}) async {
    final ReceivePort receivePort= ReceivePort();
    final args = LdkNodeArgs(
        host: host,
        port: port,
        username: username,
        password: password,
        network: network,
        path: path ?? "~/Library/Developer/CoreSimulator/Devices/8AFA2EBF-F65B-446A-B731-FF811EEFD54D/data/Containers/Data/Application/9A7D9E46-E4FA-4A2D-A68F-998612BC5A7C/Documents" ,
        isolatePort: receivePort.sendPort);
    await Isolate.spawn(_ldkInit, args);
    receivePort.listen(( message) {
     print('Ldk Node Successfully Created \nNode Id: $message');
    });
  }

  _ldkInit( LdkNodeArgs node) async {
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
  Future<LdkNodeInfo> getNodeInfo() async {
    final res = await loaderApi.getNodeInfo();
    return res;
  }
  Future<String> openChannel({required String peerPubKey, required int port, required String host, required int amountInSats, required bool isPublic})async{
    final channels = await getAllChannels();
    for(var e  in channels){
      if(e.peerPubkey == peerPubKey ){
        throw ChannelException(message: "Multiple channels unsupported: Already connected to peer $peerPubKey");
      }
    }
    final peerAddStr = "$host:$port";
    final res = await loaderApi.openChannel(peerAddStr: peerAddStr,  isPublic: isPublic, amount: amountInSats, pubKeyStr: peerPubKey);
    print(res);
    return res;
  }
  Future<List<ChannelInfo>> getAllChannels() async {
    final res = await loaderApi.listChannel();
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
