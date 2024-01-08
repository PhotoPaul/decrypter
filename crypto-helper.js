async function encryptMessage(publicKey, message) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(message);
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    dataBuffer
  );
  return encryptedData;
}

async function decryptMessage(privateKey, message) {
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    privateKey,
    base64ToArrayBuffer(message)
  );
  return new TextDecoder().decode(decrypted);
}

function pemToCryptoPublicKey(pemPublicKey) {
  // Fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----\n";
  const pemContents = pemPublicKey.substring(pemHeader.length, pemPublicKey.length - pemFooter.length);

  // Convert from a Base64 string to an ArrayBuffer
  const binaryDer = base64ToArrayBuffer(pemContents);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

function pemToCryptoPrivateKey(pemPrivateKey) {
  // Fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN RSA PRIVATE KEY-----";
  const pemFooter = "-----END RSA PRIVATE KEY-----";
  const pemContents = pemPrivateKey.substring(pemHeader.length, pemPrivateKey.length - pemFooter.length);

  // Base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);

  // Convert from a binary string to an ArrayBuffer
  const binaryDer = base64ToArrayBuffer(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

async function fetchPublicKey(serverUrl) {
  const response = await fetch(serverUrl);
  const publicKey = await response.text();
  return publicKey;
}

async function cryptoPublicKeyToPEM(publicKey) {
  return window.crypto.subtle.exportKey("spki", publicKey)
    .then(keyData => {
      const keyString = arrayBufferToBase64(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatPublicKeyAsPem(base64Key);
      return pemKey;
    });
}

async function cryptoPrivateKeyToPEM(privateKey) {
  return window.crypto.subtle.exportKey("pkcs8", privateKey)
    .then(keyData => {
      const keyString = arrayBufferToBase64(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatPrivateKeyAsPem(base64Key);
      return pemKey;
    });
}

function formatPublicKeyAsPem(str) {
  let finalString = '-----BEGIN PUBLIC KEY-----\n';
  while (str.length > 0) {
    finalString += str.substring(0, 64) + '\n';
    str = str.substring(64);
  }
  finalString += "-----END PUBLIC KEY-----";
  return finalString;
}

function formatPrivateKeyAsPem(str) {
  let finalString = '-----BEGIN RSA PRIVATE KEY-----\n';
  while (str.length > 0) {
    finalString += str.substring(0, 64) + '\n';
    str = str.substring(64);
  }
  finalString += "-----END RSA PRIVATE KEY-----";
  return finalString;
}

function arrayBufferToBase64(buffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

async function generateKeyPair() {
  let keyPair = await window.crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-256" },
  }, true, ["encrypt", "decrypt"]);

  keyPair.pemPublicKey = await cryptoPublicKeyToPEM(keyPair.publicKey);
  keyPair.pemPrivateKey = await cryptoPrivateKeyToPEM(keyPair.privateKey);

  return keyPair;
}