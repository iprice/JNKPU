# JNKPU
Java Network Key Protector Unlocker (for Bitlocker Network Unlock)

Please note, while this work is covered under the GPLv3 or later, you may run into patent issues if you attempt to
commercially redistribute this.  Please see Microsoft open protocols, patents, etc pages for more information.

An implementation of the MS-NKPU protocol in Java
(See https://msdn.microsoft.com/en-us/library/hh537327.aspx)

Can be used to remotely unlock your Bitlocker drives, assuming you have a TPM, PXE, wired network, Domain (Samba is fine), etc etc :P

Makes use of the BouncyCastle cryptography libraries. (https://www.bouncycastle.org/latest_releases.html)
Get bcprov-jdk*.jar and bcpkix-jdk*.jar

May also require Java Cryptography Exceptions Unlimited Strength Jurisdiction Policy.

Requires a PKCS8 RSA Private Key in a file, with no password.  This must be the private key that matches the Network Unlock certificate installed into the computers (probably via Domain Policy).

Generation of the key and configuration of the Microsoft environment is currently beyond the scope of this document.  It's already out there well enough.

Put BouncyCastle in your CLASSPATH, compile the code, and start the unlocker with
java net.coagulate.JNKPU.NetworkUnlock <private-keyfile>

Will require administrative privileges on most operating systems due to binding to a reserved port (BOOTPS)

Note this is /not/ a full DHCP or BOOTP server, nor, most likely (due to port conflicts) will you be able to run it on the same IP address as a DHCP/BOOTP server.

Sample run:

```# java net.coagulate.JNKPU.NetworkUnlock /etc/networkunlock.key
Java Network Key Protector Unlocker version 1.0.0 (20170830)
Sent unlock packet to /10.1.1.11:68
```
(exciting!  also the client machine successfully unlocks)
