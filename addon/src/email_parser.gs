function parseEmail(message) {
  const headers = message.getHeader("Authentication-Results");
  const sender = message.getFrom();
  const replyTo = message.getReplyTo();
  const subject = message.getSubject();
  const body = message.getBody();
  const returnPath = message.getHeader("Return-Path");
  const recieved = message.getHeader("Recieved");

  const result = {
    from: sender,
    replyTo: replyTo,
    subject: subject,
    body: body,
    returnPath: returnPath,
    authResults: headers,
    recieved: recieved,
  };

  return result;
}
