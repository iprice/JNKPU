/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.coagulate.JNKPU;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.DestroyFailedException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**  Cryptographic hooks for NKPU.
 *
 * @author Iain Price
 */
public class Cryptography {
    
    /** Initialise the crypto
     * Loads the private key and makes sure it will perform
     * @param filename The private key, in PKSC8 format, with no password
     */
    public static void init(String filename) {
        try {
            loadPrivateKey(filename);
            Cipher rsa=Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE,key);
        } catch (NoSuchPaddingException|NoSuchAlgorithmException ex) {
            System.err.println("Failed to load RSA algorithm - "+ex); System.exit(1);
        } catch (InvalidKeyException ex) {
            System.err.println("Failed to initialise RSA cipher with key - "+ex); System.exit(1);
        }
    }

    private static PrivateKey key=null;

    /** Load the actual key
     * 
     * @param filename Filename of the private key (PKCS8, No password)
     */
    private static void loadPrivateKey(String filename) {
        File f=new File(filename);
        FileInputStream fis;
        try {
            fis = new FileInputStream(f);
            byte[] rawkey;
            try (DataInputStream dis = new DataInputStream(fis)) {
                rawkey = new byte[(int)f.length()];
                dis.readFully(rawkey);
            }
            PKCS8EncodedKeySpec keyspec=new PKCS8EncodedKeySpec(rawkey);
            KeyFactory kf=KeyFactory.getInstance("RSA");
            key=kf.generatePrivate(keyspec);
        } catch (FileNotFoundException ex) {
            System.err.println("Unable to load private key file "+filename+", file not found?");
            System.exit(1);
        } catch (IOException ex) {
            System.err.println("IOException loading private key:"+ex.toString());
            System.exit(1);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Failed to load RSA encryption provider, check your Java installation (? - "+ex.toString()+")");
            System.exit(1);
        } catch (InvalidKeySpecException ex) {
            System.err.println("Invalid private key - is it in PKCS8 format with no password? ("+ex.toString()+")");
            System.exit(1);
        }
    }
    
    /** Unloads the private key.
     * This method assumes the key's destroy() has any meaningful security.  The documentation says it does, which is nice.
     */
    public static void unloadPrivateKey() throws DestroyFailedException {
        if (key==null) { return; }
        key.destroy();
        key=null;
    }
    
    /** Decrypt client provided RSA payload
     * The client sends us the CK+SK all encrypted with our public key.  Here we decrypt that payload.
     * @param clientpayload The encrypted CK+SK payload
     * @return The decrypted CK+SK payload
     */
    static byte[] decrypt(byte[] clientpayload) throws UnlockException {
        try {
            Cipher rsa=Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE,key);
            return rsa.doFinal(clientpayload);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new UnlockException("Failed to load RSA algorithm?  After pre-flight checks passed?",ex);
        } catch (NoSuchPaddingException ex) {
            throw new UnlockException("Failed to load padding type? After pre-flight checks passed?",ex);
        }   catch (InvalidKeyException ex) {
            throw new UnlockException("Invalid key exception? After pre-flight checks passed?",ex);
        }   catch (IllegalBlockSizeException ex) {
            throw new UnlockException("Illegal block size in payload",ex);
        } catch (BadPaddingException ex) {
            throw new UnlockException("Bad padding in payload",ex);
        }
    }
    /** Encrypt reply as client requires.
     * Uses AES-CCM with 256bit AES key, zero nonce (12 bytes) and a MAC.
     * @param sk AES256 Key (Session Key)
     * @param headeredck Plaintext (Client Key with prepended header)
     * @return The AES-CCM encrypted form of headeredck encrypted with the SK, as per protocol specifications.
     * @throws UnlockException 
     */
    static byte[] encrypt(byte[] sk, byte[] headeredck) throws UnlockException {
        try {
            if (headeredck.length!=44) { throw new UnlockException("We expected 44 bytes of data to encrypt, 12 byte header + 32 byte CK, but got "+headeredck.length+" bytes to encrypt"); }
            // the response uses 12 bytes of zero nonce
            byte[] nonce=new byte[12]; for (int nonceinit=0;nonceinit<nonce.length;nonceinit++) { nonce[nonceinit]=0; }
            // and no additional authenticate traffic
            byte[] empty=new byte[0];
            // the mode is AES-CCM with 256bit AES, roughly defined in rfc3610, called AES-CCM-CBC or counter with mac, and various other things.
            // note the microsoft implementation stores the MAC at the start of the encrypted reply, rather than at the end, which is what we will end up getting here from BouncyCastle.
            // the main receiver code handles the re-ordering

            // a CCM engine, based around AES
            CCMBlockCipher ccm=new CCMBlockCipher(new AESEngine());
            // the relevant parameters - the key, 16 octets of MAC, 12 byte zero nonce, and no additional authenticated data
            ccm.init(true,new AEADParameters(new KeyParameter(sk),16*8,nonce,empty));
            // output must be this long given the 44 byte input
            byte[] out=new byte[60];
            ccm.processBytes(headeredck,0,headeredck.length,out,0);
            ccm.doFinal(out,0);
            return out;
        } catch (IllegalStateException ex) {
            throw new UnlockException("AES-CCM reported illegal state?",ex);
        } catch (InvalidCipherTextException ex) {
            throw new UnlockException("Encrypting reply failed",ex);
        }
    }

    /** Convert between BouncyCastle ordering and MS ordering.
     * Unlike the RFC's recommendation, Microsoft put the MAC at the start of the payload, while implementations
     * (including BouncyCastle, and also the Scandium implementation used by Eclipse's Californium)
     * place the MAC after the message (which probably makes sense given stream ciphers are involved).
     * Here, we reorganise the payload and move the 16 byte MAC to the start, followed by the 44 byte payload.
     * @param responsepayload The CRYPT+MAC ordered payload
     * @return The payload in MAC+CRYPT format, as required by Bitlocker
     */
    static byte[] reorderMac(byte[] responsepayload) {
        // MAC goes on start...
        byte[] out=new byte[responsepayload.length];
        System.arraycopy(responsepayload,44,out,0,16);
        System.arraycopy(responsepayload,0,out,16,44);
        return out;
    }
}
