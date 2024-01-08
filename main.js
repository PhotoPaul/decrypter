var keys = {};

async function fetchAndEncrypt(message) {
  keys = {
    proxy: { pemPublicKey: await fetchPublicKey(document.getElementById("proxyUrl").value) },
    resolver: { pemPublicKey: await fetchPublicKey(document.getElementById("resolverUrl").value) }
  };
  keys.proxy.publicKey = await pemToCryptoPublicKey(keys.proxy.pemPublicKey);
  // keys.resolver.publicKey = await pemToCryptoPublicKey(keys.resolver.pemPublicKey);
  document.getElementById('proxyEncryptedURL').value = await encrypt(message);
}

async function encrypt(message) {
  let response = await encryptMessage(keys.proxy.publicKey, message);
  return arrayBufferToBase64(response);
}

async function decrypt(message) {
  keys.proxy.pemPrivateKey = document.getElementById("privateKey").value;
  let privateKey = await pemToCryptoPrivateKey(keys.proxy.pemPrivateKey);

  let response = await decryptMessage(privateKey, message);
  // let response = await decryptMessage(keys.proxy.privateKey, message);
  document.getElementById('decrypted').value = response;
}

async function generateKeys() {
  keys.proxy = await generateKeyPair();
  keys.resolver = await generateKeyPair();
}