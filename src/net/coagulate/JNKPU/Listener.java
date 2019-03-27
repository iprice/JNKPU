/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.coagulate.JNKPU;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

/** This class handles the common elements of a bitlocker server implementation.
 * This class listens to the network, and performs the necessary steps to convert a request into a reply.
 * Protocol specific elements are delegated to subclasses.
 * @author Iain Price
 */
public abstract class Listener extends Thread{

    private static final boolean DEBUG=false; // debug the packet content at various stages
    protected DatagramSocket socket;

    @Override
    public void run() {
        // common behaviour
        try {
            while (true) {
                try {
                    // the packets are far smaller than this
                    byte[] rx = new byte[2048];
                    byte[] tx = new byte[2048];
                    // block for receive
                    DatagramPacket rxp = new DatagramPacket(rx, rx.length);
                    socket.receive(rxp);

                    if (DEBUG) { System.out.println("Packet received from "+rxp.getAddress()+":"+rxp.getPort()+" len:"+rxp.getLength()); }

                    byte[] content=new byte[rxp.getLength()];
                    System.arraycopy(rxp.getData(),0,content,0,rxp.getLength());
                    byte[] clientpayload=getPayload(content);
                    dumpBuffer("Raw packet",clientpayload);
                    if (DEBUG) { 
                        if (clientpayload==null) { System.out.println("Did not decode a valid BITLOCKER payload from this packet"); }
                    }
                    if (clientpayload!=null) {
                        dumpBuffer("Client payload",clientpayload);
                        // decode the payload
                        byte[] decryptedpayload=Cryptography.decrypt(clientpayload);
                        dumpBuffer("Decrypted payload",decryptedpayload);
                        // split the payload (Client Key and Session Key, the client key is the plaintext we're going to return, sort of (see below) and the sesion key is the per session AES key)
                        byte[] ck=getCK(decryptedpayload);
                        byte[] sk=getSK(decryptedpayload);
                        dumpBuffer("CK",ck);
                        dumpBuffer("SK",sk);
                        // the client key has a header apparently, something bitlocker specific (as advised by Microsoft)
                        byte[] headeredck=headerCK(ck);
                        dumpBuffer("Headered CK",headeredck);
                        // encrypt it
                        byte[] responsepayload=Cryptography.encrypt(sk,headeredck);
                        dumpBuffer("Encrypted text",responsepayload);
                        // move the MAC from the end to the start (Microsoft specific detail?)
                        byte[] responsepayloadreordered=Cryptography.reorderMac(responsepayload);
                        dumpBuffer("Reorganised payload",responsepayloadreordered);
                        // encode it into a protocol specific reply packet
                        byte[] responsepacket=constructPayload(responsepayloadreordered,rxp.getData());
                        dumpBuffer("Reply packet",responsepacket);
                        // address it
                        DatagramPacket response=new DatagramPacket(responsepacket,responsepacket.length,rxp.getAddress(),getReplyPort());
                        socket.send(response);
                        System.out.println("Sent unlock packet to "+response.getAddress()+":"+response.getPort());
                    }
                }
                // these exceptions are per-packet and cause the unlock to stop, but the thread carries on and waits for the next packet.
                catch (UnlockException e) { System.out.println("Failed unlock:"+e.toString()); }
            }
        }
        // these exceptions are run() wide and cause the entire thread to exit, whoops :P
        catch (SocketException e)
        {
            System.err.println("FATAL: Socket error with "+socket+" - "+e.toString());
        } catch (IOException ex) {
            System.err.println("FATAL: IO Exception with "+socket+" - "+ex.toString());
        }
    }
    
    /** Dump packets as strings of hex
     * Only IF DEBUG
     * @param str Description of data
     * @param array Data
     */
    private static void dumpBuffer(String str,byte[] array) {
        if (!DEBUG) { return; }
        System.out.println("===== "+str+" ("+array.length+") =====");
        String concat="";
        for (int i=0;i<array.length;i++) {
                String b=Integer.toHexString(array[i]&0xff); 
                if (b.length()<2) { b="0"+b; }
                System.out.print(" "+b);
                concat=concat+b;
        }
        System.out.println();
        System.out.println(concat);
    }
    
    /** Extract client payload.
     * 
     * This method must process the protocol packet and extract (and reassemble if necessary) the RSA encrypted client payload, which contains the Client Key and Session Key
     * @param packet The packet content
     * @return The encrypted content of the packet, or NULL if the packet does not conform to MS-NKPU specifications (we are NOT a dhcp server, many packets are not interesting!)
     */
    abstract byte[] getPayload(byte[] packet) throws UnlockException;
    /** Wrap reply payload.
     * Protocol specific
     * @param encryptedcontent The buffer we wish to send back, already encrypted
     * @param originalpacket The original received packet, for reference (such as cloning headers)
     * @return A UDP packet content we can send to achieve unlock
     */
    abstract byte[] constructPayload(byte[] encryptedcontent,byte[] originalpacket) throws UnlockException;
    /** UDP reply port
     * @return The UDP port we reply to.
     */
    abstract int getReplyPort();



    
    // some common helper functions for the Bitlocker protocol formats (MS-NKPU)
        
    
    /** Get CK from start of payload
     * 
     * @param concat The concatenated decrypted CK+SK
     * @return The CK
     */
    byte[] getCK(byte[] concat) {
        byte[] ck=new byte[32];
        System.arraycopy(concat,0,ck,0,32);
        return ck;
    }
    /** Get SK from end of payload
     * 
     * @param concat The concatenated decrypted CK+SK
     * @return The SK
     */
    byte[] getSK(byte[] concat) {
        byte[] sk=new byte[32];
        System.arraycopy(concat,32,sk,0,32);
        return sk;
    }
    
    /** Pre-pend header to CK
     * There is an "implementation specific" header on bitlocker replies.  Here we deal with that.
     * @param rawck The raw client key (32 byte)
     * @return The client key with 12 byte header, 44 bytes total.
     */
    byte[] headerCK(byte[] rawck) {
        byte[] ck=new byte[32+12]; // 32 bytes (the payload its self) + 12 bytes of static header
        ck[0]=(byte)0x2c;
        ck[1]=(byte)0x00;
        ck[2]=(byte)0x00;
        ck[3]=(byte)0x00;
        ck[4]=(byte)0x01;
        ck[5]=(byte)0x00;
        ck[6]=(byte)0x00;
        ck[7]=(byte)0x00;
        ck[8]=(byte)0x06;
        ck[9]=(byte)0x20;
        ck[10]=(byte)0x00;
        ck[11]=(byte)0x00; 
        System.arraycopy(rawck,0,ck,12,32);
        return ck;
    }
    




    
}
