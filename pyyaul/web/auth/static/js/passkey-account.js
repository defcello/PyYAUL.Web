(function() {
  var form = document.getElementById("passkey-register-form");
  var status = document.getElementById("passkey-register-status");

  if (!form || !window.PublicKeyCredential || !navigator.credentials) {
    if (form) {
      form.hidden = true;
    }
    return;
  }

  function setStatus(message) {
    status.hidden = !message;
    status.textContent = message || "";
  }

  function base64UrlToBytes(value) {
    var normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    var padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    var binary = atob(padded);
    return Uint8Array.from(binary, function(char) { return char.charCodeAt(0); });
  }

  function bytesToBase64Url(value) {
    var bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer);
    var binary = "";
    bytes.forEach(function(byte) { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function decodeCreation(json) {
    var publicKey = json.publicKey;
    publicKey.challenge = base64UrlToBytes(publicKey.challenge);
    publicKey.user.id = base64UrlToBytes(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(credential) {
        return Object.assign({}, credential, { id: base64UrlToBytes(credential.id) });
      });
    }
    return { publicKey: publicKey, mediation: json.mediation };
  }

  function encodeCredential(credential) {
    return JSON.stringify({
      id: credential.id,
      rawId: bytesToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bytesToBase64Url(credential.response.attestationObject),
        clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
        authenticatorData: credential.response.authenticatorData ? bytesToBase64Url(credential.response.authenticatorData) : "",
        publicKey: credential.response.publicKey ? bytesToBase64Url(credential.response.publicKey) : "",
        publicKeyAlgorithm: credential.response.publicKeyAlgorithm || 0
      },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || ""
    });
  }

  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("");
    var button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      var startResponse = await fetch(form.dataset.passkeyOptionsUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(new FormData(form)).toString()
      });
      var startPayload = await startResponse.json().catch(function() { return {}; });
      if (!startResponse.ok) {
        throw new Error(startPayload.error || "Unable to start passkey registration.");
      }
      var credential = await navigator.credentials.create(decodeCreation(startPayload));
      if (!credential) {
        throw new Error("No passkey was created.");
      }
      var finishResponse = await fetch(form.dataset.passkeyFinishUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: encodeCredential(credential)
      });
      var finishPayload = await finishResponse.json().catch(function() { return {}; });
      if (!finishResponse.ok) {
        throw new Error(finishPayload.error || "Passkey registration failed.");
      }
      window.location.reload();
    } catch (error) {
      setStatus(error.message || "Passkey registration failed.");
    } finally {
      button.disabled = false;
    }
  });
})();
