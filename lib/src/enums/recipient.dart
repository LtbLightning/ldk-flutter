

/// Specifies the recipient of an invoice, to indicate to [`KeysInterface::sign_invoice`] what node
/// secret key should be used to sign the invoice.
 enum Recipient {
  /**
   * The invoice should be signed with the local node secret key.
   */
  LDKRecipient_Node,
  /**
   * The invoice should be signed with the phantom node secret key. This secret key must be the
   * same for all nodes participating in the [phantom node payment].
   *
   * [phantom node payment]: PhantomKeysManager
   */
  LDKRecipient_PhantomNode,

}