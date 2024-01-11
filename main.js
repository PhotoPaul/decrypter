var keys = {};

async function encrypt(message) {
  const proxyUrl = document.getElementById("proxyUrl").value;
  const resolverUrl = document.getElementById("resolverUrl").value;

  const proxyPublicKeyAsPEM = await fetchPublicKey(proxyUrl);
  const resolverPublicKeyAsPEM = await fetchPublicKey(resolverUrl);

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
  const proxyUrl = document.getElementById("proxyUrl").value;
  const resolverUrl = document.getElementById("resolverUrl").value;

  const resolverEncryptedFBPacket = document.getElementById('resolverEncryptedFBPacket').value;
  const resolverDecryptedFBPacket = await privateKeyDecryptMessage(resolverUrl, resolverEncryptedFBPacket);
  const resolverDecryptedFBPacketObj = JSON.parse(resolverDecryptedFBPacket);
  const proxyEncryptedURL = JSON.stringify(resolverDecryptedFBPacketObj.proxyEncryptedURL);
  
  const proxyDecryptedFBPacket = await privateKeyDecryptMessage(proxyUrl, proxyEncryptedURL);
  document.getElementById('decryptedURL').value = proxyDecryptedFBPacket;

}