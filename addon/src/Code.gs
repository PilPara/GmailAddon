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

  const hour = Number(
    Utilities.formatDate(new Date(), event.userTimezone.id, "H"),
  );

  let message;
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

function getSeverityEmoji(verdict) {
  // NOTE: Map severity level to emoji for visual distinction in plain text
  const emojis = {
    Critical: "🔴",
    High: "🟠",
    Medium: "🟡",
    Low: "🟢",
    Note: "✅",
  };
  return emojis[verdict] || "⚪";
}

function buildVerdictSection(result) {
  // NOTE: Top section — verdict with emoji and score summary
  const emoji = getSeverityEmoji(result.verdict);
  const verdictText = emoji + "  <b>" + result.verdict + "</b>";

  const scoreText =
    "Score: " +
    result.score +
    "  |  Likelihood: " +
    result.likelihood +
    "/9" +
    "  |  Impact: " +
    result.impact +
    "/9";

  const section = CardService.newCardSection();

  section.addWidget(CardService.newDecoratedText().setText(verdictText));

  section.addWidget(CardService.newTextParagraph().setText(scoreText));

  return section;
}

function buildActionsSection(actions) {
  // NOTE: Recommended actions based on detected signals and severity
  const section = CardService.newCardSection().setHeader(
    "⚡ Recommended Actions",
  );

  for (let i = 0; i < actions.length; i++) {
    section.addWidget(
      CardService.newDecoratedText().setText(actions[i]).setWrapText(true),
    );
  }

  return section;
}

function buildSignalsSection(signals) {
  // NOTE: All detected signals grouped for readability
  const section = CardService.newCardSection().setHeader("🔍 Detected Signals");

  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    const label = signal.label;
    const details = signal.user_details || signal.details;

    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(label)
        .setText(details)
        .setWrapText(true),
    );
  }

  return section;
}

function onGmailMessageOpen(event) {
  const accessToken = event.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const messageId = event.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const emailData = parseEmail(message);
  const result = sendToBackend(emailData);

  Logger.log(JSON.stringify(emailData));

  // NOTE: Email info header
  const header = CardService.newCardHeader()
    .setTitle("UpWind Guard")
    .setSubtitle(emailData.from);

  // NOTE: Build card sections
  const verdictSection = buildVerdictSection(result);
  const actionsSection = buildActionsSection(result.actions);
  const signalsSection = buildSignalsSection(result.signals);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(actionsSection)
    .addSection(signalsSection)
    .build();
}
