document.addEventListener("DOMContentLoaded", function() {
  // Auto-check current tab URL
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const url = tabs[0]?.url;
      if (url) {
          document.getElementById("url-input").value = url;
          checkPhishing(url, "check-result");
      }
  });

  // Manual URL check form
  document.getElementById("url-form").addEventListener("submit", function(event) {
      event.preventDefault();
      const url = document.getElementById("url-input1").value.trim();
      if (url) {
          checkPhishing(url, "manual-result");
      }
  });
});

async function checkPhishing(url, resultElementId) {
  const resultDiv = document.getElementById(resultElementId);
  resultDiv.textContent = "Analyzing URL...";
  resultDiv.className = "status-pending";

  try {
      if (!isValidUrl(url)) {
          throw new Error("Please enter a valid URL (e.g., https://example.com)");
      }

      const response = await fetch(`http://localhost:8000/api?url=${encodeURIComponent(url)}`);
      
      if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.msg || `Server responded with status ${response.status}`);
      }

      const data = await response.json();
      displayResult(data, resultDiv);
  } catch (error) {
      console.error("Error:", error);
      resultDiv.textContent = error.message;
      resultDiv.className = "status-error";
  }
}

function displayResult(data, resultDiv) {
  resultDiv.textContent = data.msg;
  
  if (data.prediction === "phishing") {
      resultDiv.className = "status-phishing";
  } else if (data.prediction === "legitimate") {
      resultDiv.className = "status-legitimate";
  } else {
      resultDiv.className = "status-error";
  }
}

function isValidUrl(url) {
  try {
      new URL(url);
      return true;
  } catch {
      return false;
  }
}