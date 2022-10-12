
class ChannelException implements Exception {
  final String message;
  ChannelException({required this.message}) ;
  @override
  String toString() {
    return 'ChannelException: $message';
  }
}