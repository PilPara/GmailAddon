function onHomepage(event) {
  const userEmail = Session.getActiveUser().getEmail();
  const userName = userEmail.split("@")[0];

  const header = CardService.newCardHeader().setTitle(
    "📧 Email Threat Scanner",
  );

  const greeting = CardService.newTextParagraph().setText(
    "👋 Hello, " + userName + "!",
  );

  const instructions = CardService.newTextParagraph().setText(
    "Open an email to scan it for threats. The analysis will appear here automatically.",
  );

  const section = CardService.newCardSection()
    .addWidget(greeting)
    .addWidget(instructions);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
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
  const emojis = {
    Critical: "🔴",
    High: "🟠",
    Medium: "🟡",
    Low: "🔵",
    Note: "🟢",
  };
  return emojis[verdict] || "⚪";
}

function getSeveritySummary(verdict) {
  const summaries = {
    Critical:
      "This email is almost certainly malicious. Delete it immediately.",
    High: "This email has strong signs of being malicious. Do not interact with it.",
    Medium:
      "This email has some suspicious elements. Be cautious before taking any action.",
    Low: "This email is mostly safe but has minor indicators worth noting.",
    Note: "This email appears safe. No threats detected.",
  };
  return summaries[verdict] || "Unable to determine email safety.";
}

function buildVerdictSection(result) {
  const emoji = getSeverityEmoji(result.verdict);
  const section = CardService.newCardSection().setHeader("Verdict");

  section.addWidget(
    CardService.newDecoratedText().setText(
      emoji +
        "  <b>" +
        (result.verdict === "Note" ? "No Risk" : result.verdict + " Risk") +
        "</b>",
    ),
  );

  section.addWidget(
    CardService.newTextParagraph().setText(getSeveritySummary(result.verdict)),
  );

  return section;
}

function buildActionsSection(actions) {
  const section = CardService.newCardSection().setHeader(
    "⚡ What You Should Do",
  );

  for (let i = 0; i < actions.length; i++) {
    section.addWidget(
      CardService.newDecoratedText().setText(actions[i]).setWrapText(true),
    );
  }

  return section;
}

function isAuthPass(label) {
  const passLabels = ["SPF Passed", "DKIM Passed", "DMARC Passed"];
  return passLabels.indexOf(label) !== -1;
}

function isAuthSignal(label) {
  const prefixes = ["SPF", "DKIM", "DMARC"];
  for (let i = 0; i < prefixes.length; i++) {
    if (label.indexOf(prefixes[i]) === 0) {
      return true;
    }
  }
  return false;
}

function isCleanSignal(label) {
  const cleanLabels = [
    "Domain Match",
    "Domain Subdomain Match",
    "Reply-To Match",
    "Reply-To Subdomain Match",
    "Links Clean",
    "No Links Found",
    "No Attachments",
    "Social Engineering: None",
  ];
  return cleanLabels.indexOf(label) !== -1;
}

function isInfoOnlySignal(label) {
  if (label.indexOf("Urgency: None") === 0) return true;
  if (label.indexOf("Urgency: Low") === 0) return true;
  return false;
}

function isAttachmentFound(label) {
  return label === "Attachment Found";
}

function addFindingWidget(card, text) {
  const section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText().setText(text).setWrapText(true),
  );
  card.addSection(section);
}

function buildCard(header, verdictSection, actionsSection, signals) {
  const card = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(actionsSection);

  const findingsHeader =
    CardService.newCardSection().setHeader("🔍 What We Found");
  findingsHeader.addWidget(CardService.newTextParagraph().setText(""));
  card.addSection(findingsHeader);

  let authPassCount = 0;
  let authFailSignals = [];
  let warningSignals = [];
  let infoSignals = [];
  let safeAttachmentCount = 0;
  let hasAttachmentWarning = false;

  for (let i = 0; i < signals.length; i++) {
    const label = signals[i].label;
    if (
      label === "Dangerous File Type" ||
      label === "Macro-Enabled File" ||
      label === "Double Extension Detected"
    ) {
      hasAttachmentWarning = true;
      break;
    }
  }

  for (let i = 0; i < signals.length; i++) {
    const signal = signals[i];
    const label = signal.label;
    const details = signal.user_details || signal.details;

    if (isAuthPass(label)) {
      authPassCount++;
      continue;
    }

    if (isAuthSignal(label) && !isAuthPass(label)) {
      authFailSignals.push({ label: label, details: details });
      continue;
    }

    if (isAttachmentFound(label)) {
      safeAttachmentCount++;
      continue;
    }

    if (isCleanSignal(label) || isInfoOnlySignal(label)) {
      infoSignals.push({ label: label, details: details });
      continue;
    }

    warningSignals.push({ label: label, details: details });
  }

  if (authPassCount === 3) {
    addFindingWidget(
      card,
      "Email authentication passed — sent from a legitimate mail server, but this doesn't guarantee the sender is trustworthy",
    );
  } else if (authPassCount > 0) {
    addFindingWidget(
      card,
      "Email authentication partially passed (" +
        authPassCount +
        "/3 checks) — proceed with caution",
    );
  }

  for (let i = 0; i < authFailSignals.length; i++) {
    addFindingWidget(card, "⚠️ " + authFailSignals[i].details);
  }

  for (let i = 0; i < warningSignals.length; i++) {
    addFindingWidget(card, "⚠️ " + warningSignals[i].details);
  }

  if (safeAttachmentCount > 0 && !hasAttachmentWarning) {
    addFindingWidget(
      card,
      safeAttachmentCount +
        " attachment(s) — no dangerous file types detected ✓",
    );
  } else if (safeAttachmentCount > 0 && hasAttachmentWarning) {
    addFindingWidget(card, safeAttachmentCount + " attachment(s) found");
  }

  for (let i = 0; i < infoSignals.length; i++) {
    addFindingWidget(card, infoSignals[i].details);
  }

  return card.build();
}

function onGmailMessageOpen(event) {
  const accessToken = event.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const messageId = event.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const emailData = parseEmail(message);
  const result = sendToBackend(emailData);

  Logger.log(JSON.stringify(emailData));

  const header = CardService.newCardHeader().setTitle(
    "From: " + emailData.from,
  );

  const verdictSection = buildVerdictSection(result);
  const actionsSection = buildActionsSection(result.actions);

  return buildCard(header, verdictSection, actionsSection, result.signals);
}
