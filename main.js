async function encrypt() {
  // let keyPair = generateKeyPair();
  let publicKeys = await fetchPublicKeys();
  publicKeys.proxyPublicKeyImported = await pemPublicKeyToWebKey(publicKeys.proxyPublicKey);
  publicKeys.resolverPublicKeyImported = await pemPublicKeyToWebKey(publicKeys.resolverPublicKey);

  let message = document.getElementById('url').value;
  let response = await encryptMessage(publicKeys.proxyPublicKeyImported, message);
  document.getElementById('encrypted').value = btoa(String.fromCharCode.apply(null, new Uint8Array(response)));
}