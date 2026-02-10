// Learn more about extending Gmail with Google Workspace add-ons at https://developers.google.com/workspace/add-ons/gmail

//  function on(event) {
//    var accessToken = event.gmail.accessToken;
//    var messageId = event.gmail.messageId;
//    GmailApp.setCurrentMessageAccessToken(accessToken);
//    var mailMessage = GmailApp.getMessageById(messageId);
//    var from = mailMessage.getFrom();
//    var senderImage = "";

//    var openDocButton = CardService.newTextButton()
//        .setText("open docs")
//        .setOpenLink(
//            CardService.newOpenLink().setUrl("https://developers.google.com/gmail/add-ons/"));

//    var cardHeader = CardService.newCardHeader().setTitle("UpWind Guard").setImageStyle(CardService.ImageStyle.CIRCLE).setImageUrl("https://www.upwind.io/wp-content/uploads/2026/01/genericArtboard-1-copy-6-1.png");

//    var cardSection = CardService.newCardSection();

//    return CardService.newCardBuilder().setHeader(cardHeader).addSection(cardSection).build();

// }

function onHomepage(event) {
  const time = Utilities.formatDate(
    new Date(),
    event.commonEventObject.timeZone.id,
    "HH:mm",
  );
  const header = CardService.newCardHeader().setTitle("title");
  const text = CardService.newTextParagraph().setText(time);
  const section = CardService.newCardSection()
    .setHeader("Time:")
    .addWidget(text);

  var hour = Number(
    Utilities.formatDate(new Date(), event.userTimezone.id, "H"),
  );
  var message;
  if (hour >= 6 && hour < 12) {
    message = "Good morning";
  } else if (hour >= 12 && hour < 18) {
    message = "Good afternoon";
  } else {
    message = "Good night";
  }
  message += " " + event.hostApp;

  const text1 = CardService.newTextParagraph().setText(message);
  const section1 = CardService.newCardSection().addWidget(text1);
  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .addSection(section1)
    .build();
}

function getSender(event) {
  const accessToken = event.gmail.accessToken;
  const messageId = event.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const mailMessage = GmailApp.getMessageById(messageId);
  const sender = mailMessage.getFrom();
  return sender;
}

function onGmailMessageOpen(event) {
  const title = "UpWind Guard";
  const upWindlogoAdress =
    "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fawsmp-logos.s3.amazonaws.com%2Fseller-iya3gfu2j7n3a%2Fc127beb0e792c982c402c952ef9d6663.png&f=1&nofb=1&ipt=bcc5c52cf070710ad6d0bef80a2dfbf57d36a2fc6695c3bbba7c292023a5257d";
  const logo = CardService.newImage().setImageUrl(upWindlogoAdress);

  const header = CardService.newCardHeader()
    .setTitle(title)
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl(upWindlogoAdress);

  const text = CardService.newTextParagraph().setText(
    "Maliciousness score placeholder",
  );
  const section = CardService.newCardSection()
    .setHeader("Section Header")
    .addWidget(text);

  sender = getSender(event);
  Logger.log(sender);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}
