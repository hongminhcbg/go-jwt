##go-jwt

I. HS256

  SHA256 = hash data to 256 bit

  HMAC: message + secret + hashFunc = signature

  HMAC+SHA256 = HS256

  Must share secret between servers

I. RS256 

RSA + SHA256

Using RSA secret to generate token and public to verify token.

If another server want to verify token you should share public key, not private key

