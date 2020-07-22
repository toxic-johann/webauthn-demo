const handler = require('serve-handler');
const http = require('http');
const cbor = require('cbor');
const crypto = require('crypto');

let publicKey;

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
  if (!Buffer.isBuffer(pkBuffer))
      throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

  let type;
  if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
      /*
          If needed, we encode rawpublic key to ASN structure, adding metadata:
          SEQUENCE {
            SEQUENCE {
               OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
               OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
            }
            BITSTRING <raw public key>
          }
          Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
      */
      
      pkBuffer = Buffer.concat([
          new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
          pkBuffer
      ]);

      type = 'PUBLIC KEY';
  } else {
      type = 'CERTIFICATE';
  }

  let b64cert = pkBuffer.toString('base64');

  let PEMKey = '';
  for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
      let start = 64 * i;

      PEMKey += b64cert.substr(start, 64) + '\n';
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
  
  return PEMKey
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
  let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
  let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
  let flags         = flagsBuf[0];
  let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
  let counter       = counterBuf.readUInt32BE(0);

  return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
  return crypto.createHash('SHA256').update(data).digest();
}

const server = http.createServer(async (req, res) => {
  if (req.url.startsWith('/webauthn/response')) {
    let body = '';
    req.on('data', function(chunk) {
      body += chunk;
    });
    req.on('end', function() {
      const credential = JSON.parse(body);
      const [decodedAttestationObj] = cbor.decodeAllSync(
        Buffer.from(credential.response.attestationObject, 'base64'));

      const {authData} = decodedAttestationObj;

      // get the length of the credential ID
      const dataView = new DataView(
          new ArrayBuffer(2));
      const idLenBytes = authData.slice(53, 55);
      idLenBytes.forEach(
          (value, index) => dataView.setUint8(
              index, value));
      const credentialIdLength = dataView.getUint16();

      // get the credential ID
      const credentialId = authData.slice(
          55, 55 + credentialIdLength);

      // get the public key object
      const publicKeyBytes = authData.slice(
          55 + credentialIdLength);

      console.warn(publicKeyBytes);

      // the publicKeyBytes are encoded again as CBOR
      const publicKeyObject = cbor.decodeAllSync(
          publicKeyBytes);
      console.log(publicKeyObject)

      publicKey = publicKeyBytes;

      res.statusCode = 200;
      res.end('Hello World');
    });
    return;
  }

  if (req.url.startsWith('/webauthn/login')) {
    let body = '';
    req.on('data', function(chunk) {
      body += chunk;
    });
    req.on('end', function() {
      const credential = JSON.parse(body);
      console.warn(credential);
      const authenticatorData = Buffer.from(credential.response.authenticatorData, 'base64');
      let authrDataStruct  = parseGetAssertAuthData(authenticatorData);
      let clientDataHash   = hash(Buffer.from((credential.response.clientDataJSON, 'base64')))
      let signatureBase    = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);
      let publicKeyA = ASN1toPEM(publicKey);
      const signature = Buffer.from(credential.response.signature, 'base64');
      console.warn(authenticatorData, publicKeyA, publicKey);
      const result = crypto.createVerify('SHA256')
        .update(signatureBase)
        .verify(publicKeyA, signature);
      console.warn(result);

      res.statusCode = 200;
      res.end('Hello World');
    });
    return;
  }
  await handler(req, res);
}).listen(80);
