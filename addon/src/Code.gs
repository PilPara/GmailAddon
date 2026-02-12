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
  const emojis = {
    Critical: "🔴",
    High: "🟠",
    Medium: "🟡",
    Low: "🟢",
    Note: "✅",
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

function getNormalizedScore(rawScore) {
  const MAX_RAW_SCORE = 81;
  const NORMALIZED_MAX = 100;
  return Math.round((rawScore / MAX_RAW_SCORE) * NORMALIZED_MAX);
}

function getScoreLabel(normalizedScore) {
  if (normalizedScore <= 12) return "Very low risk";
  if (normalizedScore <= 30) return "Low risk";
  if (normalizedScore <= 55) return "Moderate risk";
  if (normalizedScore <= 80) return "High risk";
  return "Critical risk";
}

function buildVerdictSection(result) {
  const emoji = getSeverityEmoji(result.verdict);
  const normalizedScore = getNormalizedScore(result.score);
  const scoreLabel = getScoreLabel(normalizedScore);
  const section = CardService.newCardSection();

  section.addWidget(
    CardService.newDecoratedText().setText(
      emoji + "  <b>" + result.verdict + "</b>",
    ),
  );

  section.addWidget(
    CardService.newTextParagraph().setText(getSeveritySummary(result.verdict)),
  );

  section.addWidget(
    CardService.newTextParagraph().setText(
      "Risk Score: " + normalizedScore + " / 100 — " + scoreLabel,
    ),
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

function buildFindingsSection(signals) {
  const section = CardService.newCardSection().setHeader("🔍 What We Found");

  let authPassCount = 0;
  let authFailSignals = [];
  let warningSignals = [];
  let infoSignals = [];
  let safeAttachmentCount = 0;
  let hasAttachmentWarning = false;

  // NOTE: Check if any attachment has a warning signal
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

  // NOTE: Auth summary
  if (authPassCount === 3) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(
          "Sender identity verified — this email is really from who it claims ✓",
        )
        .setWrapText(true),
    );
  } else if (authPassCount > 0) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(
          "Sender identity partially verified (" +
            authPassCount +
            "/3 checks passed)",
        )
        .setWrapText(true),
    );
  }

  // NOTE: Auth failures
  for (let i = 0; i < authFailSignals.length; i++) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText("⚠️ " + authFailSignals[i].details)
        .setWrapText(true),
    );
  }

  // NOTE: Warnings (dangerous attachments, mismatches, etc.)
  for (let i = 0; i < warningSignals.length; i++) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText("⚠️ " + warningSignals[i].details)
        .setWrapText(true),
    );
  }

  // NOTE: Safe attachment summary
  if (safeAttachmentCount > 0 && !hasAttachmentWarning) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(
          safeAttachmentCount +
            " attachment(s) — no dangerous file types detected ✓",
        )
        .setWrapText(true),
    );
  } else if (safeAttachmentCount > 0 && hasAttachmentWarning) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(safeAttachmentCount + " attachment(s) found")
        .setWrapText(true),
    );
  }

  // NOTE: Info signals
  for (let i = 0; i < infoSignals.length; i++) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(infoSignals[i].details)
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

  const header = CardService.newCardHeader().setTitle(
    "From: " + emailData.from,
  );

  const verdictSection = buildVerdictSection(result);
  const actionsSection = buildActionsSection(result.actions);
  const findingsSection = buildFindingsSection(result.signals);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(actionsSection)
    .addSection(findingsSection)
    .build();
}
