const uploadForm = document.getElementById("uploadForm");
const fileInput = document.getElementById("emailFile");
const selectedFile = document.getElementById("selectedFile");
const analyzeButton = document.getElementById("analyzeButton");
const statusText = document.getElementById("status");
const loadingSection = document.getElementById("loading");
const resultsSection = document.getElementById("results");
const dropZone = document.querySelector(".drop-zone");

function setText(id, value, fallback = "Not available") {
  document.getElementById(id).textContent = value || fallback;
}

function addListItems(id, items, fallbackText, formatter = null) {
  const list = document.getElementById(id);

  list.innerHTML = "";

  if (!items || items.length === 0) {
    const item = document.createElement("li");
    item.textContent = fallbackText;
    list.appendChild(item);
    return;
  }

  items.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = formatter ? formatter(value) : value;
    list.appendChild(item);
  });
}

function formatAttachment(attachment) {
  const filename = attachment.filename || "unknown_attachment";
  const contentType = attachment.content_type || "unknown type";
  const size = attachment.size_bytes || 0;

  return `${filename} | ${contentType} | ${size} bytes`;
}

function getAuthStatus(authenticationResults, protocol) {
  const authText = (authenticationResults || []).join(" ").toLowerCase();

  if (authText.includes(`${protocol}=pass`)) {
    return "PASS";
  }

  if (
    authText.includes(`${protocol}=fail`) ||
    authText.includes(`${protocol}=softfail`)
  ) {
    return "FAIL";
  }

  if (authText.includes(`${protocol}=neutral`)) {
    return "NEUTRAL";
  }

  return "UNKNOWN";
}

function setAuthStyle(id, status) {
  const element = document.getElementById(id);

  element.textContent = status;
  element.classList.remove("good-text", "bad-text", "neutral-text");

  if (status === "PASS") {
    element.classList.add("good-text");
  } else if (status === "FAIL") {
    element.classList.add("bad-text");
  } else {
    element.classList.add("neutral-text");
  }
}

function getRiskConfig(score) {
  if (score >= 75) {
    return {
      label: "HIGH RISK",
      color: "#ff6682",
    };
  }

  if (score >= 40) {
    return {
      label: "SUSPICIOUS",
      color: "#ffd166",
    };
  }

  return {
    label: "LOW RISK",
    color: "#64f6b1",
  };
}

function updateRiskRing(score) {
  const circle = document.getElementById("riskCircle");
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const safeScore = Math.min(Math.max(score, 0), 100);
  const offset = circumference - (safeScore / 100) * circumference;

  const config = getRiskConfig(safeScore);

  circle.style.strokeDasharray = circumference;
  circle.style.strokeDashoffset = offset;
  circle.style.stroke = config.color;

  const badge = document.getElementById("threatBadge");
  badge.textContent = config.label;
  badge.style.color = config.color;
  badge.style.borderColor = config.color;
}

function showRelayPath(headers) {
  const relayPath = document.getElementById("relayPath");

  relayPath.innerHTML = "";

  if (!headers || headers.length === 0) {
    const noHeader = document.createElement("div");

    noHeader.className = "relay-step";
    noHeader.dataset.hop = "—";
    noHeader.textContent =
      "No Received headers were found in the uploaded email.";

    relayPath.appendChild(noHeader);
    return;
  }

  const orderedHeaders = [...headers].reverse();

  orderedHeaders.forEach((header, index) => {
    const relayStep = document.createElement("div");

    relayStep.className = "relay-step";
    relayStep.dataset.hop = String(index + 1);
    relayStep.textContent = header;

    relayPath.appendChild(relayStep);
  });
}

function updateSelectedFile() {
  if (fileInput.files.length > 0) {
    selectedFile.textContent = `Selected evidence: ${fileInput.files[0].name}`;
  } else {
    selectedFile.textContent = "No email evidence selected";
  }
}

fileInput.addEventListener("change", updateSelectedFile);

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
  });
});

dropZone.addEventListener("drop", (event) => {
  const droppedFiles = event.dataTransfer.files;

  if (!droppedFiles.length) {
    return;
  }

  if (!droppedFiles[0].name.toLowerCase().endsWith(".eml")) {
    statusText.textContent = "Only .eml files are supported.";
    return;
  }

  fileInput.files = droppedFiles;
  updateSelectedFile();
});

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!fileInput.files.length) {
    statusText.textContent = "Please choose a .eml evidence file.";
    return;
  }

  const selected = fileInput.files[0];

  if (!selected.name.toLowerCase().endsWith(".eml")) {
    statusText.textContent = "Only .eml files are supported.";
    return;
  }

  const formData = new FormData();
  formData.append("email_file", selected);

  statusText.textContent = "";
  loadingSection.classList.remove("hidden");
  resultsSection.classList.add("hidden");

  analyzeButton.disabled = true;
  analyzeButton.innerHTML = "<span>Analyzing Evidence...</span><b>◌</b>";

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      body: formData,
    });

    const result = await response.json();

    if (!response.ok || result.success === false) {
      throw new Error(result.error || "Email analysis failed.");
    }

    const emailData = result.email_data || {};
    const riskData = result.risk_analysis || {};
    console.log("result.ips:", result.ips);
    console.log("emailData.ips_found:", emailData.ips_found);
    console.log("emailData.ips_found:", emailData.ips_found);

    setText("caseId", result.case_id);
    setText("analysisTime", `Analysis time: ${result.analysis_time}`);
    setText("originalFilename", result.original_filename || selected.name);
    setText("hash", result.evidence_sha256);

    setText("threatCategory", riskData.threat_category);
    setText("riskScore", riskData.risk_score, "0");
    setText("confidence", riskData.confidence);
    setText("recommendedAction", riskData.recommended_action);

    const score = Number(riskData.risk_score || 0);
    updateRiskRing(score);

    setText("from", emailData.from);
    setText("replyTo", emailData.reply_to);
    setText("returnPath", emailData.return_path);
    setText("subject", emailData.subject);
    setText("emailDate", emailData.date);
    setText("messageId", emailData.message_id);

    setText(
      "bodyPreview",
      emailData.body_preview,
      "No readable email body was found.",
    );

    const authResults = emailData.authentication_results || [];

    setText(
      "authResults",
      authResults.join("\n"),
      "No Authentication-Results header was found.",
    );

    setAuthStyle("spfStatus", getAuthStatus(authResults, "spf"));

    setAuthStyle("dkimStatus", getAuthStatus(authResults, "dkim"));

    setAuthStyle("dmarcStatus", getAuthStatus(authResults, "dmarc"));

    addListItems(
      "riskReasons",
      riskData.reasons,
      "No major risk indicators found.",
    );

    addListItems("urls", emailData.urls, "No URLs found in email content.");

    addListItems(
      "ips",
      emailData.ips_found,
      "No IP addresses found in Received headers.",
    );

    // Fill the geolocation textarea with extracted IPs
    if (result.ips && Array.isArray(result.ips)) {
      document.getElementById("ips").value = result.ips.join(", ");
    } else if (emailData.ips_found && Array.isArray(emailData.ips_found)) {
      document.getElementById("ips").value = emailData.ips_found.join(", ");
    } else {
      document.getElementById("ips").value = "";
    }

    addListItems(
      "attachments",
      emailData.attachments,
      "No attachments found.",
      formatAttachment,
    );

    showRelayPath(emailData.received_headers);

    document.getElementById("downloadReport").href = result.report_url || "#";

    resultsSection.classList.remove("hidden");

    resultsSection.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });

    statusText.textContent = "Analysis completed successfully.";
  } catch (error) {
    statusText.textContent = `Error: ${error.message}`;
  } finally {
    loadingSection.classList.add("hidden");
    analyzeButton.disabled = false;
    analyzeButton.innerHTML = `
      <span>Start Forensic Analysis</span>
      <b>→</b>
    `;
  }
});
