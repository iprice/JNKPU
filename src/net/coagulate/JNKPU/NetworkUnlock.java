package net.coagulate.JNKPU;

import java.io.IOException;



/** Implements MS-NKPU.
 * Network Key Protector Unlocker, for unlocking Bitlocker encrypted drives.
 * Requires BouncyCastle for crypto.
 * Possibly requires a Java Security Policy Update file since the key size is >128 bits.
 * @author Iain Price 
 */

public class NetworkUnlock {

	public static final boolean DEBUG=false;
        public static final String VERSION="1.1.0";
        public static final String RELEASE="20190327";
        
        private static boolean startipv4=true;
        private static boolean startipv6=true;
        private static boolean strict=true;
        private static String keyfile=null;

	public static void main(String args[]) {

            System.out.println("Java Network Key Protector Unlocker version "+VERSION+" ("+RELEASE+")");
            //-----
            parseArguments(args);
            //-----
            // Load the private key and run pre-flight checks on the cryptography providers
            if (keyfile==null || keyfile.isEmpty()) { System.err.print("You must specify a key file"); usage(); System.exit(1); }
            System.out.println("Loading private key...");
            Cryptography.init(keyfile);
            //-----
            if (startipv4) {
                try {
                    System.out.println("Starting DHCP listener on IPv4...");
                    DHCPv4 listenerv4=new DHCPv4();
                    listenerv4.start();
                } catch (IOException e) {
                    System.err.println("Failed to start IPv4 listener: "+e.getLocalizedMessage());
                    if (strict) { System.exit(1); }
                }
            }
            //-----
            if (startipv6) {
                try {
                    System.out.println("Starting DHCP listener on IPv6...");
                    DHCPv6 listenerv6=new DHCPv6();
                    listenerv6.start();
                } catch (IOException e) {
                    System.err.println("Failed to start IPv6 listener: "+e.getLocalizedMessage());
                    if (strict) { System.exit(1); }
                }
            }
            //-----
            System.out.println("Startup is complete, ready to service requests.");
        }
        
    private static void usage() {
        System.out.println("Usage: java net.coagulate.JNKPU.NetworkUnlock [--noipv4] [--noipv6] [--strict] <keyfile>");
        System.out.println("  --noipv4 - disable the IPv4 DHCP listener/responder (default is to start the IPv4 listener).");
        System.out.println("  --noipv6 - disable the IPv6 DISH listener/responder (default is to start the IPv6 listener).");
        System.out.println("  --strict - if any listener fails to start, exit (default is not to exit, so IPv6 may fail and IPv4 will still run).");
        System.out.println("  keyfile  - path to Network Unlock private key in PKCS8 format with no password.");
    }

    private static void parseArguments(String[] args) {
        if (args.length<1) { return; }
        keyfile=args[args.length-1];
        for (int i=0;i<(args.length-1);i++) {
            boolean caught=false;
            String arg=args[i];
            if (arg.equalsIgnoreCase("--noipv4")) { startipv4=false; caught=true; }
            if (arg.equalsIgnoreCase("--noipv6")) { startipv6=false; caught=true; }
            if (arg.equalsIgnoreCase("--strict")) { strict=true; caught=true; }
            if (!caught) { System.err.println("Unknown parameter '"+arg+"'"); usage(); System.exit(1); }
        }
    }
}
