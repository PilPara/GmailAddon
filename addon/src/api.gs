function sendToBackend(emailData) {
  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(emailData),
  };

  const response = UrlFetchApp.fetch(CONFIG.BACKEND_URL, options);
  return JSON.parse(response.getContentText());
}
