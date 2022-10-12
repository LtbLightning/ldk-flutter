import 'dart:core';



import 'package:ldk_flutter/ldk_flutter.dart';
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
class AcceptChannel {
  final ffi.Int ptr;

  AcceptChannel(Object _dummy, this.ptr) :super();

  getTemporaryChannelId() {
    // final ldkPtr = malloc<LDKAcceptChannel>()..ref = LDKAcceptChannel as LDKAcceptChannel;
    // List x = loaderApi.AcceptChannel_get_temporary_channel_id(this.ptr)
    //   return  x;
    // }
  }
  /// A temporary channel ID, until the funding outpoint is announced
  void setTemporaryChannelId( List<ffi.Int> val) {
  }

  /// The threshold below which outputs on transactions broadcast by sender will be omitted
  getDustLimitSatoshis() {

    return 256;
  }

  /// The threshold below which outputs on transactions broadcast by sender will be omitted
  void setDustLimitSatoshis(ffi.Int val) {
  }

  /// The maximum inbound HTLC value in flight towards sender, in milli-satoshi
  getMaxHtlcValueInFlightMsat() {
    return 0;
  }


  /// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
  getChannelReserveSatoshis() {

  }

  /// The minimum value unencumbered by HTLCs for the counterparty to keep in the channel
  void setChannelReserveSatoshis(ffi.Int val) {

  }




  /// Used to derive an HTLC payment key to sender for transactions broadcast by counterparty
  List<ffi.Int> getHtlcBasePoint() {
    return   List.empty();
  }

  /// Used to derive an HTLC payment key to sender for transactions broadcast by counterparty
  void setHtlcBasePoint(List<ffi.Int>val) {

  }

  /// The first to-be-broadcast-by-sender transaction's per commitment point
  List<ffi.Int> getFirstPerCommitmentPoint() {
    return   List.empty();
  }

  /// The first to-be-broadcast-by-sender transaction's per commitment point
  void setFirstPerCommitmentPoint(List<ffi.Int>val) {

    // loaderApi.AcceptChannel_set_first_per_commitment_point(this.ptr, val);

  }

  /// The channel type that this channel will represent. If none is set, we derive the channel
  /// type from the intersection of our feature bits with our counterparty's feature bits from
  /// the Init message.
  ///
  /// This is required to match the equivalent field in [`OpenChannel::channel_type`].
  ///
  /// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None

  getChannelType() {
    //LDKChannelTypeFeatures
    return 1;
  }

  /// The channel type that this channel will represent. If none is set, we derive the channel
  /// type from the intersection of our feature bits with our counterparty's feature bits from
  /// the Init message.
  ///
  /// This is required to match the equivalent field in [`OpenChannel::channel_type`].
  ///
  /// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
  void setChannelType( dynamic val) {
  }

  /// Creates a copy of the AcceptChannel
  // LDKAcceptChannel clone() {
  //   final  ret = loaderApi.AcceptChannel_clone(ptr);
  //   return ret;
  // }

  /// Serialize the AcceptChannel object into a byte array which can be read by AcceptChannel_read
  List write() {
    return List.empty();
  }

}