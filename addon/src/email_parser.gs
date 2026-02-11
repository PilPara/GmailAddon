function parseEmail(message) {
  const headers = message.getHeader("Authentication-Results");
  const sender = message.getFrom();
  const replyTo = message.getReplyTo();
  const subject = message.getSubject();
  const body = message.getBody();
  const returnPath = message.getHeader("Return-Path");
  const received = message.getHeader("Received");
  const attachments = message.getAttachments();
  const attachmentData = [];

  for (let i = 0; i < attachments.length; ++i) {
    const attachment = attachments[i];
    const bytes = attachment.getBytes();

    // const hash = Utilities.computeDigest(
    //   Utilities.DigestAlgorithm.SHA_256,
    //   bytes,
    // );
    // const hexHash = hash
    //   .map(function (byte) {
    //     const hex = (byte < 0 ? byte + 256 : byte).toString(16);
    //     return hex.length === 1 ? "0" + hex : hex;
    //   })
    //   .join("");
    //
    attachmentData.push({
      filename: attachment.getName(),
      mimeType: attachment.getContentType(),
      size: bytes.length,
      // hash: hexHash,
    });
  }

  const result = {
    from: sender,
    replyTo: replyTo,
    subject: subject,
    body: body,
    returnPath: returnPath,
    authResults: headers,
    received: received,
    attachments: attachmentData,
  };

  return result;
}
