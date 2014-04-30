#EasyCryptography.Net

This library provides easy access to ```System.Security.Cryptography```
It designed for easiness, not for diversity or powerful functions

*.Net Framework 3.5 or above REQUIRED*

##How to use

```C#
//using statement
using Variel.Security;

//How to hash data (SHA1/256/512, MD5 Supported)
string sha256Hash = Hash.SHA256Hash("This string will be hashed");

//How to encrypt and decrypt data symmetrically (AES(Rijndael) Supported)
byte[] salt = Guid.NewGuid().ToByteArray(); //Create a salt;
byte[] data = Encoding.UTF8.GetBytes("This is Normal String");
byte[] encryptedData = Cryptography.EncryptAES("This is the KEY", salt, data);
byte[] decryptedData = Cryptography.DecryptAES("This is the KEY", salt, encryptedData);

//How to encrypt and decrypt data asymmetrically (RSA Supported)
RSAParameters key = Cryptography.CreateRSAParameter();
byte[] data = Encoding.UTF8.GetBytes("This is Normal String");
byte[] encryptedData = Cryptography.EncryptRSA(data, key);
byte[] decryptedData = Cryptography.DecryptRSA(encryptedData, key);
```

##Licence

You **CAN DO ANYTHING** but some conditions below **MUST** be keeped:

1. **DO NOT CHANGE** Namespace.
2. **WRITE** "VARIEL" or [this GitHub page url](http://variel.kr/easycrypto) on credit of your product.
3. Feel free to be a contributor.
