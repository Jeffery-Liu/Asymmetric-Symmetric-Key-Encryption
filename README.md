# Asymmetric-Symmetric-Key-Encryption
Cyber Security Project:
- Asymmetric Key Encryption &amp; Digital Signature Verification. 
- Encrypted Client-Server Communication with Symmetric-Key and Asymmetric-Key. 

# Warning
- This implementation specifies the cipher "RSA", which usually refers to RSA with PKCS#1 v1.5 in Java. Sadly, this cipher is vulnerable to a Bleicherbacher oracle attack allowing an active attacker to recover the plain text of a sent message. To mitigate the issue, please change to OAEP which can be used by changing the cipher to "RSA/ECB/OAEPWithSHA-256AndMGF1Padding".

## Contributors:
- Jinfeng (Jeffery) Liu <liujinfeng1209@gmail.com>
- Zhipeng (Lance) Men <lance_mon@icloud.com>
