/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.coagulate.JNKPU;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

/** Implements the DHCPv4 specific parts of NKPU
 *
 * @author Iain Price
 */
public class DHCPv4 extends Listener {
    
    private static final boolean DEBUG=false;
    
    // Open the listener at initialisation
    public DHCPv4() {
        try { socket = new DatagramSocket(67); }
        catch (SocketException e) { System.err.println("Failed to bind to IPV4 DHCP port (67) - "+e.toString()); }
    }

    /** Returns the ADM payload from the DHCPv4 packet.
     * The payload is split into two sections within two vendor codes.
     * There should also be a vendor specific identifier of BITLOCKER
     * @param b The byte array for the DHCPv4 packet contents
     * @return The ADM, which is the encrypted CK+SK, or null if this packet does not conform to Bitlocker specifications.
     */
    @Override
    byte[] getPayload(byte[] b) {
        
        // the encrytped CK+SK ADM element we are after is 256 bytes 
        byte[] reply=new byte[256];
        int i=0; // i for index! into buffer.
        // we're not really a proper BOOTP server and we dont care about... well, almost anything in the BOOTP header, skip it
        i+=(1+1+1+1+4+2+2+4+4+4+4+16+64+128);  // see RFC951, skipping the entire BOOTP header up to and including the boot file name.  Now pointing into vendor section 1 (if present)
        
        // next 4 bytes should be the "magic number" 0x63 0x82 0x53 0x63 (see RFC1497 - bootp vendor extensions)
        if (b[i]!=(byte)0x63 || b[i+1]!=(byte)0x82 || b[i+2]!=(byte)0x53 || b[i+3]!=(byte)0x63) {
                if (DEBUG) { System.out.println("BOOTP packet received with invalid vendor extension magic cookie");  // this is probably not interesting since we receive /all/ dhcp/bootp traffic
                        //for (int j=0;j<4;j++) { System.out.println("Magic#"+j+":"+Integer.toHexString(b[i+j] & 0xff)); }
                }
                return null;
        }
        i+=4;

        // now, the vendor extensions come in blocks, each block has a byte ID header, then a byte length header, allowing us to skip irrelevant stuff
        // while we're still within the receive block, and the Vendor ID is not 255 ("end")
        boolean marker=false; //bitlocker "tagged"
        int index1=0; // location of first half of the key protector
        int index2=0; // location of the second half of the key protector
        // while we're still inside the buffer, and the next "byte ID header" isn't 255 (which marks end of the packet)
        while (i<b.length && b[i]!=(byte)255) {
            // get the block's vendor code
            int vendorcode=b[i] & 0xff; i++;  // make unsigned

            // 0 and 255 are '1 byte' (no payload)
            // we should never have 255 here anyway
            if (vendorcode!=0 && vendorcode!=255) {
                    // the rest have a 1 byte length, which we can use to skip.
                    int length=b[i] & 0xff; i++;  // note we load this into an int.  bytes are signed, which is problematic here ^^

                    // VENDOR CODE SPECIFIC PROCESSING
                    // vendor code 60 should contain BITLOCKER
                    if (vendorcode==(byte)60) { 
                            String data=new String(b,i,length);
                            if (data.equals("BITLOCKER")) { marker=true; }
                    }
                    if (vendorcode==(byte)0x7d) { // vendor specific extension
                            if (b[i]==(byte)0x00 && b[i+1]==(byte)0x00 && b[i+2]==(byte)0x01 && b[i+3]==(byte)0x37) { // microsoft specific identifier
                                    // the 2nd half of the KP ADM is contained herein, after the microsoft header
                                    index2=i+4;
                                    // also skip 1 byte data length (redundant?), suboption code, and suboption length, both of which are 1 byte and "well known"
                                    index2+=3;
                            } else {
                                    if (DEBUG) { System.out.println("Unexpected vendor field enterprise ID"); for (int j=0;j<4;j++) { System.out.println("Magic#"+j+":"+Integer.toHexString(b[i+j] & 0xff)); } }
                            }

                    }
                    if (vendorcode==(byte)0x2b) { // vendor specific information standard structure
                            // bit of a cludge here.  the data is basically 1 byte 0x01, 1 byte length = 0x14(10_20) and then a 20 byte sha-1 cert thumbprint.
                            // since we only support one cert, we dont really care, if its the wrong thumbprint the decrypt will fail later anyway
                            // so, 20 bytes +1 (length) +1 (header) = 22 bytes later
                            // 1 byte 0x02 (header)
                            // 1 byte length, which will always be 128 because its the other half of the key protector
                            index1=i+24;
                    }

                    // END VENDOR CODE SPECIFIC PROCESSING
                   i+=length;
            }
        }

        // we exited, should be because of vendor END code
        if (b[i]!=(byte)255) {
            if (DEBUG) { System.out.println("NOTE: Parsing of packet ended without END marker"); }
            return null;
        }

        // must be the BITLOCKER tag in the packet
        if (!marker) {
            if (DEBUG) { System.out.println("There was no bitlocker header on the received packet"); }
            return null;
        }
        // must have found both halves of the payload
        if (index1==0 || index2==0) {
            if (index1==0 && DEBUG) { System.out.println("Missing part one of the ADM package"); }
            if (index2==0 && DEBUG) { System.out.println("Missing part two of the ADM package"); }
            return null;
        }
        
        // copy out the payload
        System.arraycopy(b,index1,reply,0,128);
        System.arraycopy(b,index2,reply,128,128);

        return reply;
    }

    
    
    /** Write the encrypted content into a BOOTP reply packet
     * Most of this code is just "random" numbers
     * @param encryptedcontent The payload we are sending back to the client
     * @param b The original packet for reference
     * @return A fully formed UDP BOOTP reply packet
     * @throws UnlockException If there is a problem with the supplied data
     */
    @Override
    byte[] constructPayload(byte[] encryptedcontent,byte b[]) throws UnlockException {
        if (encryptedcontent.length!=60) { throw new UnlockException("Reply payload is "+encryptedcontent.length+" bytes long but we expect 60"); }
        byte[] r=new byte[256+60]; // happens to be the size
        r[0]=2; // message type: boot reply
        r[1]=1; // type ethernet
        r[2]=6; // hardware address length
        r[3]=0; //hops
        r[4]=b[4]; r[5]=b[5]; r[6]=b[6]; r[7]=b[7]; // 4 byte transaction id we copy from the inbound (same place)
        r[8]=0; r[9]=0; // seconds elapsed
        r[10]=(byte)0x80; r[11]=0; // bootpflags
        r[12]=0; r[13]=0; r[14]=0; r[15]=0; // client IP, zeros in server response
        r[16]=0; r[17]=0; r[18]=0; r[19]=0; // next IP, zeros in server response
        r[20]=0; r[21]=0; r[22]=0; r[23]=0; // relay IP, zeros in server response
        r[24]=0; r[25]=0; r[26]=0; r[27]=0; // relay IP, zeros in server response
        r[28]=b[28]; r[29]=b[29]; r[30]=b[30]; r[31]=b[31]; r[32]=b[32]; r[33]=b[33]; // clone client mac
        for (int x=34;x<=236;x++) { r[x]=0; } // lots of stuff we dont use 
        
        r[236]=0x63; r[237]=(byte)0x82; r[238]=0x53; r[239]=0x63; //dhcp magic header
        r[240]=0x3c; // vendor class identifier
        r[241]=0x9; // length
        r[242]=0x42; //B
        r[243]=0x49;//I
        r[244]=0x54;//T
        r[245]=0x4c;//L
        r[246]=0x4f;//O
        r[247]=0x43;//C
        r[248]=0x4b;//K
        r[249]=0x45;//E
        r[250]=0x52;//R
        r[251]=0x2b; // option 43, vendor specific information...
        r[252]=62;//length (not hex :P)
        r[253]=2; // is reply code
        r[254]=60; // length of the payload
        System.arraycopy(encryptedcontent, 0, r, 255, encryptedcontent.length);
        r[255+encryptedcontent.length]=(byte)0xff; // END
        return r;       
    }
    
    @Override
    int getReplyPort() {
        return 68; // such a complex method :) see IANA assignments for "Well Known Ports", this is officially known as BOOTPC, Boot Protocol Client port.
    }
    

    
}
