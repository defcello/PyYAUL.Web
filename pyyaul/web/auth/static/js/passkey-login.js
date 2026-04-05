(function() {
  var passkeyUI = document.getElementById("passkey-login-ui");
  var button = document.getElementById("passkey-login-button");
  var status = document.getElementById("passkey-login-status");
  var rememberMe = document.querySelector('input[name="persistCookies"]');

  if (!passkeyUI || !button || !window.PublicKeyCredential || !navigator.credentials) {
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

  function decodeRequest(json) {
    var publicKey = json.publicKey;
    publicKey.challenge = base64UrlToBytes(publicKey.challenge);
    if (publicKey.allowCredentials) {
      publicKey.allowCredentials = publicKey.allowCredentials.map(function(credential) {
        return Object.assign({}, credential, { id: base64UrlToBytes(credential.id) });
      });
    }
    return { publicKey: publicKey, mediation: json.mediation };
  }

  function encodeAssertion(credential) {
    return JSON.stringify({
      id: credential.id,
      rawId: bytesToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bytesToBase64Url(credential.response.authenticatorData),
        clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
        signature: bytesToBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle ? bytesToBase64Url(credential.response.userHandle) : ""
      },
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment || ""
    });
  }

  async function shouldShowPasskeyLogin() {
    try {
      if (PublicKeyCredential.getClientCapabilities) {
        var caps = await PublicKeyCredential.getClientCapabilities();
        return !!(caps.passkeyPlatformAuthenticator || caps.conditionalGet || caps.hybridTransport);
      }
      if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
      return true;
    } catch (_error) {
      return false;
    }
  }

  async function handleLoginClick() {
    setStatus("");
    button.disabled = true;
    try {
      var startBody = new URLSearchParams();
      if (rememberMe && rememberMe.checked) {
        startBody.set("remember_me", "yes");
      }
      var startResponse = await fetch(passkeyUI.dataset.passkeyOptionsUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: startBody.toString()
      });
      var startPayload = await startResponse.json().catch(function() { return {}; });
      if (!startResponse.ok) {
        throw new Error(startPayload.error || "Unable to start passkey login.");
      }
      var credential = await navigator.credentials.get(decodeRequest(startPayload));
      if (!credential) {
        throw new Error("No passkey was selected.");
      }
      var finishResponse = await fetch(passkeyUI.dataset.passkeyFinishUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: encodeAssertion(credential)
      });
      var finishPayload = await finishResponse.json().catch(function() { return {}; });
      if (!finishResponse.ok) {
        throw new Error(finishPayload.error || "Passkey login failed.");
      }
      window.location.href = finishPayload.redirect || "/";
    } catch (error) {
      setStatus(error.message || "Passkey login failed.");
    } finally {
      button.disabled = false;
    }
  }

  shouldShowPasskeyLogin().then(function(show) {
    if (!show) {
      return;
    }
    passkeyUI.hidden = false;
    button.addEventListener("click", handleLoginClick);
  });
})();
