/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.coagulate.JNKPU;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.util.logging.Level;

/** Implements the DHCPv6 specific parts of NKPU
 *
 * Note this implementation is weak with bounds checking.
 * The JVM will prevent out of bounds reads, but the raw code assumes this protection.
 * @author Iain Price
 */
public class DHCPv6 extends Listener {
    
    private static final boolean DEBUG=false;
    
    /* According to the official NKPU specification, only the BITLOCKER identifier and the key package are required to unlock the target computer.
    * Despite this, Windows Server 2016 also returns the Client ID block and adds a Server ID block to the reply, which is possibly protocol compliant in some way.
    * Here, these extraneous parts can be turned on or off ; there is little "need" for either of them, either the key package /works/ and you unlock the disc, or it doesn't.
    * Is anyone going to not unlock the disk just because the key came from a weird server DUID?  Doesn't seem logical.  Maybe unlock and show an alert if you so care :P
    * (turns out this is exactly how it works, illogical or not)
    *
    * Note the server DUID is complete garbage, the timestamp and the mac don't even make sense.  I wrote these two blocks when testing something and figuring out MAC
    * addresses is not the most fun thing to be doing (I have some code for it somewhere).
    */
    private static final boolean INCLUDE_CLIENT_ID=false; // Seems Win10Pro.1809 doesn't care about the client ID block being mirrored.
    private static final boolean INCLUDE_SERVER_ID=true; // WIN 10 PRO release 1809 will IGNORE the DHCPv6 reply if it does not contain a SERVER ID block.  even if we just made it up.
    
    
    // Open the listener at initialisation
    public DHCPv6() throws IOException  {
        // IPv6 uses multicast rather than broadcast, on UDP 547
        MulticastSocket mcs=new MulticastSocket(547);
        mcs.joinGroup(InetAddress.getByName("ff02::1:2"));
        socket=mcs;
    }

    /** Returns the ADM payload from the DHCPv6 packet.
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
        
        // first byte is message type, for NKPU should be 11 - Information-request
        if (b[i]!=11) {
            debug("Received DHCPv6 message type "+b[i]+"; ignoring."); // probably a boring message, we get all dhcp type traffic, incl non bitlocker stuff which we need to ignore and let the real DHCP servers handle
            return null;
        }
        i++;     
        // skip transaction id for now
        i+=3;

        // comparable "block" type to DHCPv4 - a number of option blocks starting with an option code and then a length.
        // Unlike DHCPv4 these are 16 bit numbers and thus make life "easier" than the two-option-part dhcpv4 nkpu.
        boolean marker=false; //bitlocker "tagged"
        int index=0; // location of the key protector
        // while we're still inside the buffer
        while (i<b.length) {
            int option=(b[i]<<8)+b[i+1]; i+=2;
            int length=(b[i]<<8)+b[i+1]; i+=2;
            debug("DHCPv6 - option "+option+" length "+length);
            // OPTION_VENDOR_CLASS (16), used as a bitlocker marker
            if (option==16) {  
                // if this is bitlocker it's a very 'static' structure, of known length
                if (length==15) {
                    int i2=i;
                    // silly byte matching.  Is this the microsoft enterprise ID?
                    if (b[i]==(byte)0x00 && b[i+1]==(byte)0x00 && b[i+2]==(byte)0x01 && b[i+3]==(byte)0x37) {
                        i2+=4;
                        // next two bytes would be a length, it'll always be 9 by this point since we know it's static AND conforms to the earlier length
                        i2+=2;
                        byte[] optiondata=new byte[9];
                        System.arraycopy(b, i2, optiondata, 0, 9);
                        String content=new String(optiondata);
                        if (content.equals("BITLOCKER")) { marker=true; debug("Located the Bitlocker magic number header"); } // yay
                        else { debug("Magic marker of BITLOCKER came out as '"+content+"'"); }
                    } else {
                        debug("Unexpected vendor field enterprise ID"); for (int j=0;j<4;j++) { debug("Magic#"+j+":"+Integer.toHexString(b[i+j] & 0xff)); }
                    }
                } else {
                    debug("Unexpected length of vendorclass "+length+" expecting 15");
                }
            }
            // OPTION_VENDOR_OPTS (17), used for storing the ADM protected key package, or whatever its called
            if (option==17) {
                if (length==288) {
                    // all of this is mostly irrelevant to us, so here's the offset we need as "magically" calculated
                    index=i;
                    index+=4; // skip enterprise number
                    index+=4+20; // assume suboption code 1 'hash'
                    index+=4; // should skip header of suboptioncode 2 with suboptionlength 256
                    debug("Located the ADM package");
                } else {
                    debug("Unexpected vendor options data length, would be 288 for bitlocker, is "+length);
                }
            }
            i+=length;
        }
        // must have the BITLOCKER tag in the packet
        if (!marker) {
            debug("There was no bitlocker header on the received packet");
            return null;
        }
        // must have found the payload
        if (index==0) {
            debug("Missing the DHCPv6 ADM package");
            return null;
        }
        
        // copy out the payload
        System.arraycopy(b,index,reply,0,256);
        return reply;
   }

    
    
    /** Write the encrypted content into a DHCP reply packet
     * Most of this code is just "random" numbers
     * @param encryptedcontent The payload we are sending back to the client
     * @param b The original packet for reference
     * @return A fully formed DHCPv6 reply packet
     * @throws UnlockException If there is a problem with the supplied data
     */
    @Override
    byte[] constructPayload(byte[] encryptedcontent,byte b[]) throws UnlockException {
        if (encryptedcontent.length!=60) { throw new UnlockException("Reply payload is "+encryptedcontent.length+" bytes long but we expect 60"); }
        
        byte[] clientid=null;
        if (INCLUDE_CLIENT_ID) {
            clientid=extractOptionBlock(b,1);
            if (clientid==null) { throw new UnlockException("Expected a client id!"); }
        }
        
        int targetsize=4; //DHCP message id + 3 bytes transaction ID
        if (INCLUDE_SERVER_ID) { targetsize+=18; } // size of the server DUID block
        targetsize+=19; // size of the BITLOCKER block
        targetsize+=12+encryptedcontent.length; // size of the payload block
        if (INCLUDE_CLIENT_ID && clientid!=null) { targetsize+=clientid.length; } // &&!=null is unnecessary, but it makes the IDE happier :P
        byte[] r=new byte[targetsize];
        
        // first 3 of 4 bytes are the same as the request
        System.arraycopy(b,0,r,0,4);
        r[0]=7; // other than [0] which is DHCP message type which is 7-reply

        int i=4; // initial offset is after this header
        
        if (INCLUDE_SERVER_ID) {
            r[i++]=0;  r[i++]=2; // server DUID block // 18 bytes
            r[i++]=0;  r[i++]=14; // server DUID block
            r[i++]=0;  r[i++]=1; // "link layer address plus time"
            r[i++]=0;  r[i++]=1; // "hwtype ethernet"
            for (int x=0;x<10;x++) { r[i++]=(byte) (x+1); }
        }
        
        r[i++]=0;  r[i++]=0x10; // option code // 19 bytes in this block
        r[i++]=00; r[i++]=0xf; // option length
        r[i++]=0; r[i++]=0; r[i++]=1; r[i++]=0x37; // microsoft enterprise number
        r[i++]=0; r[i++]=9; // vendor class data length
        r[i++]=0x42;//B
        r[i++]=0x49;//I
        r[i++]=0x54;//T
        r[i++]=0x4c;//L
        r[i++]=0x4f;//O
        r[i++]=0x43;//C
        r[i++]=0x4b;//K
        r[i++]=0x45;//E
        r[i++]=0x52;//R        
        
        r[i++]=00; r[i++]=0x11; // option code // 12 bytes in this block, not incl key
        r[i++]=00; r[i++]=68;//0x28; // option length
        r[i++]=0; r[i++]=0; r[i++]=1; r[i++]=0x37; // microsoft enterprise number
        r[i++]=00; r[i++]=0x2; // suboption code
        r[i++]=00; r[i++]=60;//0x20; // suboption length
        System.arraycopy(encryptedcontent, 0, r, i, encryptedcontent.length); // decrypted key
        i+=encryptedcontent.length;
        if (INCLUDE_CLIENT_ID && clientid!=null) { System.arraycopy(clientid,0,r,i,clientid.length); } // null guard of IDE happiness
        return r;       
    }
    
    @Override
    int getReplyPort() {
        return 546; // such a complex method :) see IANA assignments for "Well Known Ports", this is officially known as BOOTPC, Boot Protocol Client port.
    }
    
    byte[] extractOptionBlock(byte[] b,int getoption) {
        int i=4;
        while (i<b.length) {
            int option=(b[i]<<8)+b[i+1]; i+=2;
            int length=(b[i]<<8)+b[i+1]; i+=2;
            debug("DHCPv6 - option "+option+" length "+length);
            // OPTION_VENDOR_CLASS (16), used as a bitlocker marker
            if (option==getoption) {  
                byte[] output=new byte[length+4];
                System.arraycopy(b,i-4,output,0,length+4);
                return output;
            }
            i+=length;
        }
        return null;
        
    }
 
    private void debug(String message) {
        if (DEBUG) { NetworkUnlock.logger.log(Level.FINE,message); }
    }
}
