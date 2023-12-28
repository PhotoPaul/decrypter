function encrypt() {
  let keyPair = generateKeyPair();
}

async function generateKeyPair() {
  let keyPair = await window.crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-256" },
  }, true, ["sign", "verify"]);

  console.log(await webCryptoPublicKeyToPEM(keyPair.publicKey));
  console.log(await webCryptoPrivateKeyToPEM(keyPair.privateKey));
  return keyPair;
}

async function webCryptoPublicKeyToPEM(publicKey) {
  return window.crypto.subtle.exportKey("spki", publicKey)
    .then(keyData => {
      const keyString = arrayBufferToString(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatAsPem(base64Key);
      return pemKey;
    });
}

async function webCryptoPrivateKeyToPEM(privateKey) {
  return window.crypto.subtle.exportKey("pkcs8", privateKey)
    .then(keyData => {
      const keyString = arrayBufferToString(keyData);
      const base64Key = window.btoa(keyString);
      const pemKey = formatAsPem(base64Key);
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

function formatAsPem(str) {
  let finalString = '-----BEGIN PUBLIC KEY-----\n';
  while (str.length > 0) {
    finalString += str.substring(0, 64) + '\n';
    str = str.substring(64);
  }
  finalString += "-----END PUBLIC KEY-----";
  return finalString;
}
