// ==UserScript==
// @name         TrustLink
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  Detects malicious websites using hosts lits and a machine learning model API
// @author       Ujjawal Saini, Divyanshu Shukla
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// ==/UserScript==

(function() {
  'use strict';

  // Function to send URL to the API
  function sendUrlToApi(url) {
      const apiUrl = 'http://127.0.0.1:5000/predict';
      const requestData = { url };

      GM_xmlhttpRequest({
          method: 'POST',
          url: apiUrl,
          headers: {
              'Content-Type': 'application/json'
          },
          data: JSON.stringify(requestData),
          onload: function(response) {
              handleApiResponse(response.responseText);
          }
      });
  }

  // Function to handle API response
  function handleApiResponse(responseText) {
      try {
          const result = JSON.parse(responseText);
          const highestScoreLabel = result.reduce((max, curr) => (curr.score > max.score ? curr : max), { score: -1 });

          // Check for each label individually
          if (highestScoreLabel.label !== 'benign' &&
              highestScoreLabel.label !== 'defacement' &&
              highestScoreLabel.label !== 'Phishing' &&
              highestScoreLabel.label !== 'Malware') {
              
              // Block the page with a warning message
              document.body.innerHTML = `<div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 0, 0, 0.5); z-index: 9999; text-align: center; padding-top: 50px; font-size: 24px; color: black;">This website is potentially harmful.</div>`;
          }
      } catch (error) {
          console.error('Error parsing API response:', error);
      }
  }

  // Get the current URL
  const currentUrl = window.location.href;

  // Send the URL to the API
  sendUrlToApi(currentUrl);
})();
