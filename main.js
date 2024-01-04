async function encrypt() {
  // let keyPair = generateKeyPair();
  let publicKeys = await fetchPublicKeys();
  publicKeys.proxyPublicKeyImported = await pemPublicKeyToWebKey(publicKeys.proxyPublicKey);
  publicKeys.resolverPublicKeyImported = await pemPublicKeyToWebKey(publicKeys.resolverPublicKey);
  debugger;
  let response = await encryptMessage(publicKeys.proxyPublicKeyImported, "Hello World!");
}

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

function pemPublicKeyToWebKey(pemPublicKey) {
  // Fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pemPublicKey.substring(pemHeader.length, pemPublicKey.length - pemFooter.length);
  
  // Base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  
  // Convert from a binary string to an ArrayBuffer
  const binaryDer = stringToArrayBuffer(binaryDerString);
  
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

// Function to convert string to ArrayBuffer
function stringToArrayBuffer(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

async function fetchPublicKeys() {
  const response = await fetch('https://script.google.com/macros/s/AKfycbx5-apWsu9ZWPtneyW7oNzLMsutDzG7_JtHCew2wEcacYvWjwCjp3okOFwp2YdqTU0T/exec'); // Replace with your URL
  const publicKeys = await response.json();
  return publicKeys;
}

async function generateKeyPair() {
  let keyPair = await window.crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-256" },
  }, true, ["encrypt", "decrypt"]);

  console.log(await webCryptoPublicKeyToPEM(keyPair.publicKey));
  console.log(await webCryptoPrivateKeyToPEM(keyPair.privateKey));
  return keyPair;
}

async function webCryptoPublicKeyToPEM(publicKey) {
  return window.crypto.subtle.exportKey("spki", publicKey)
    .then(keyData => {
      const keyString = arrayBufferToString(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatPublicKeyAsPem(base64Key);
      return pemKey;
    });
}

async function webCryptoPrivateKeyToPEM(privateKey) {
  return window.crypto.subtle.exportKey("pkcs8", privateKey)
    .then(keyData => {
      const keyString = arrayBufferToString(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatPrivateKeyAsPem(base64Key);
      return pemKey;
    });
}

function arrayBufferToString(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
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
