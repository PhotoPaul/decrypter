var keys = {};

async function go(message) {
  const proxyPublicKeyAsPEM = await fetchPublicKey(document.getElementById("proxyUrl").value);

  const resolverPublicKeyAsPEM = await fetchPublicKey(document.getElementById("resolverUrl").value);

  const proxyEncryptedURL = await publicKeyEncryptMessage(proxyPublicKeyAsPEM, message);
  
  const FBPacket = {
    proxyPublicKeyAsPEM: proxyPublicKeyAsPEM,
    proxyEncryptedURL: proxyEncryptedURL
  }

  const stringifiedFBPacket = JSON.stringify(FBPacket);
  const resolverEncryptedFBPacket = await publicKeyEncryptMessage(resolverPublicKeyAsPEM, stringifiedFBPacket);
  document.getElementById('resolverEncryptedFBPacket').value = JSON.stringify(resolverEncryptedFBPacket);
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