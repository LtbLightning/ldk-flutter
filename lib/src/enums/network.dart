

/// An enum representing the possible Bitcoin or test networks which we can run on
 enum Network {
  /**
   * The main Bitcoin blockchain.
   */
  LDKNetwork_Bitcoin,
  /**
   * The testnet3 blockchain.
   */
  LDKNetwork_Testnet,
  /**
   * A local test blockchain.
   */
  LDKNetwork_Regtest,
  /**
   * A blockchain on which blocks are signed instead of mined.
   */
  LDKNetwork_Signet,
}