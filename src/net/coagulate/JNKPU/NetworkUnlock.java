package net.coagulate.JNKPU;

import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.macs.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.engines.*;



/** Implements MS-NKPU.
 * Network Key Protector Unlocker, for unlocking Bitlocker encrypted drives.
 * Requires BouncyCastle for crypto.
 * Possibly requires a Java Security Policy Update file since the key size is >128 bits.
 * @author Iain Price 
 */

public class NetworkUnlock {

	public static final boolean DEBUG=false;
        public static final String VERSION="1.0.0";
        public static final String RELEASE="20170830";

	public static void main(String args[]) {

            System.out.println("Java Network Key Protector Unlocker version "+VERSION+" ("+RELEASE+")");

            // One day a better command line parser might help.
            if (args.length!=1) { System.err.println("JNKPU takes exactly one command line argument, the path to the private key (PKCS8, no password)"); System.exit(1); }
            // Load the private key and run pre-flight checks on the cryptography providers
            Cryptography.init(args[0]);
            
            // eventually we would start both DHCP4 and DHCP6 listeners here, but one thing at a time
            DHCPv4 listenerv4=new DHCPv4();
            listenerv4.start();
        }
}
