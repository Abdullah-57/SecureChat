const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, 'audit_log.json');

const logEvent = (eventType, details) => {
  const timestamp = new Date().toISOString();
  
  const logEntry = {
    timestamp,
    eventType,
    details
  };

  const logString = JSON.stringify(logEntry) + ",\n";

  fs.appendFile(LOG_FILE, logString, (err) => {
    if (err) console.error("FAILED TO WRITE LOG:", err);
  });

  console.log(`[${eventType}]`, details);
};

module.exports = { logEvent };