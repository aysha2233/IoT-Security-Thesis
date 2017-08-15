/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package iot_security_library;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.java.security.SecureRandom;


public class Encryption {
    private String ALGORITHM = "AES";
    private int DEFAULT_KEYLENGTH = 16; //In bytes, default is 128 bit key
    private final static int DEFAULT_NONCE_SIZE = 12; //Standard nonce size, any other sizes increase complexity
    private final static int DEFAULT_MAC_SIZE = 128; //Size of desired MAC, in bits (not bytes)
    public GCMBlockCipher cipher = null;
    public byte [] cipherText = null;
    public byte [] mac = null;
   


    //ENCRYPTION FUNCTIONS

    //Standard Encryption: key + text
    
    public byte[] encrypt(byte[] data, int keyOffset, int keyLength, int plaintextOffset, int plaintextLength) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ShortBufferException {
        
    	
        
        //Vars
        int offset = 16 - (plaintextLength % 16);
        byte [] paddedPlainText = null;
        
        if(offset != 16){
            paddedPlainText = new byte[plaintextLength + offset];
            System.arraycopy(data, 0,paddedPlainText , 0, plaintextLength);
            for(int i = plaintextLength; i < paddedPlainText.length; i++){
                paddedPlainText[i] = (byte)0;
            }
            Utility.printFormatedByteArray(paddedPlainText);
            System.out.println(paddedPlainText.length);
        }
        else{
            
            paddedPlainText = new byte[plaintextLength];
            System.arraycopy(data,0,paddedPlainText , 0, plaintextLength);
        }
    	//Vars
        byte [] outputBuffer = new byte [paddedPlainText.length + 16];

        //Create secret key specification
        SecretKeySpec secretKey = new SecretKeySpec(data, keyOffset, keyLength, ALGORITHM);
        //Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        //Initialize cipher with encrypt mode and secret key
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //Encrypt plain text
        cipher.doFinal(data, plaintextOffset, plaintextLength, outputBuffer, 0);
        
        this.cipherText = outputBuffer;

        return outputBuffer;
    }
    //Encrypt
    // Assumes the 'key' byte buffer contains only the key
    // Assumes the entire 'plaintext' buffer should be encrypted
    // If input is less than 16 bytes, automatically padded
    public byte[] encrypt(byte[] plainText, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ShortBufferException {

        if(key == null){
            System.out.println("Empty key");
            throw new InvalidKeyException("Empty Key");
        }
        
        //Vars
        int keyLength = key.length;
        int plaintextLength = plainText.length;
        int offset = 16 - (plaintextLength % 16);
        byte [] paddedPlainText = null;
        
        if(offset != 16){
            paddedPlainText = new byte[plaintextLength + offset];
            System.arraycopy(plainText, 0,paddedPlainText , 0, plaintextLength);
            for(int i = plaintextLength; i < paddedPlainText.length; i++){
                paddedPlainText[i] = (byte)0;
            }
            Utility.printFormatedByteArray(paddedPlainText);
            System.out.println(paddedPlainText.length);
        }
        else{
            
            paddedPlainText = new byte[plaintextLength];
            System.arraycopy(plainText,0,paddedPlainText , 0, plaintextLength);
        }
        //Create output buffer
        byte [] outputBuffer = new byte [paddedPlainText.length + 16];

        //Create secret key specification
        SecretKeySpec secretKey = new SecretKeySpec(key, 0, DEFAULT_KEYLENGTH, ALGORITHM);
        //Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        //Initialize cipher with encrypt mode and secret key
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //Encrypt plain text
        int numBytesStored = cipher.doFinal(paddedPlainText, 0, paddedPlainText.length, outputBuffer, 0 );
        
        this.cipherText = outputBuffer;

        return outputBuffer;
    }

    //DECRYPTION FUNCTIONS
    //Standard Decryption
    public byte[] decrypt(byte[] data, int keyOffset, int keyLength, int ciphertextOffset, int ciphertextLength) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ShortBufferException {

        //Init output buffer
        byte [] outputBuffer = new byte[ciphertextLength];

        //Create secret key specification
        SecretKeySpec secretKey = new SecretKeySpec(data, keyOffset, keyLength, ALGORITHM);
        //Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        //Initialize cipher with decryption mode and secret key
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //Decrypt cipher text
        int numBytesStored = cipher.doFinal(data, ciphertextOffset, ciphertextLength, outputBuffer, 0 );

        return outputBuffer;
    }
    //Standard Decryption
    public byte[] decrypt(byte[] cipherText, byte [] key) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ShortBufferException {

        int keyLength = key.length;
        int ciphertextLength = cipherText.length;
        byte [] outputBuffer = new byte[ciphertextLength];
        //Create secret key specification
        SecretKeySpec secretKey = new SecretKeySpec(key,0, keyLength, ALGORITHM);
        //Create cipher instance
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        //Initialize cipher with decryption mode and secret key
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //Decrypt cipher text
        int plainText = cipher.doFinal(cipherText, 0, ciphertextLength, outputBuffer, 0 );

        return outputBuffer;
    }

    //GCM
    //For encryption, authentication, and integrity
    //macsize: MAC size in bits
    public byte[] gcmEncrypt(byte [] key, byte[] plainText, byte [] associatedData, byte [] nonce) throws InvalidCipherTextException {


        //Set up AES/AEAD parameters
        //Default 128 bit
        BlockCipher blockCipher = new AESEngine();
        KeyParameter keyParam = new KeyParameter(key);

        //Init underlying cipher
        blockCipher.init(true, keyParam);
        AEADParameters params = new AEADParameters(keyParam, DEFAULT_MAC_SIZE, nonce, associatedData);

        //Init GCM Cipher
        int byteSizeMAC = DEFAULT_MAC_SIZE/8; //Convert MAC size to bytes
        GCMBlockCipher cipher = new GCMBlockCipher(blockCipher);

        //Create output buffer with planned output size
        cipher.init(true, params);
        byte [] output = new byte[cipher.getOutputSize(plainText.length)];

        //Process the plain text and return the offset in the output array
        int offset = cipher.processBytes(plainText,0, plainText.length,output,0);

        //Process the AAD
        cipher.processAADBytes(associatedData,0,associatedData.length);

        offset += cipher.doFinal(output, offset);
        //Get Cipher Text
        byte[] cipherText = new byte[offset - byteSizeMAC];
        this.cipherText = cipherText;
        System.arraycopy(output, 0, cipherText, 0, cipherText.length);

        //Get MAC
        byte[] authenticationTag = new byte[byteSizeMAC];
        System.arraycopy(output,offset - byteSizeMAC, authenticationTag, 0, authenticationTag.length);


        //From predefined class
        byte [] MAC = cipher.getMac();
        this.mac = cipher.getMac();
        //System.out.println("MAC from class: ");
        //Utility.printFormatedByteArray(MAC);
        
        

        return output;

    }

    //GCM decryption, authenticate the message, check message integrity
    //Returns decrypted data if MAC check passes, returns null if MAC check fails
    public byte [] gcmDecrypt(byte [] key, byte [] cipherText, byte[] associatedData, byte[] nonce) throws InvalidCipherTextException {

        //Set up AES/AEAD parameters
        //Default 128 bit
        BlockCipher blockCipher = new AESEngine();
        KeyParameter keyParam = new KeyParameter(key);


        //Init underlying cipher
        blockCipher.init(false, keyParam);
        AEADParameters params = new AEADParameters(keyParam, DEFAULT_MAC_SIZE, nonce, associatedData);

        GCMBlockCipher cipher = new GCMBlockCipher(blockCipher);
        cipher.init(false, params);
        byte [] output = new byte[cipher.getOutputSize(cipherText.length)];
        //System.out.println("output length: " + output.length);

        //Process additional data into MAC for authentication
        cipher.processAADBytes(associatedData,0,associatedData.length);
        int offset = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
        cipher.doFinal(output,offset);
        

        return output;
    }

    public static byte [] generateNonce (){
        //Generate Random nonce value
        SecureRandom nonceGen = new SecureRandom();
        nonceGen.setSeed((long)Math.random());
        byte [] nonce = new byte[DEFAULT_NONCE_SIZE];
        nonceGen.nextBytes(nonce);
        return nonce;
    }
    


    //GETTERS & SETTERS
    public String getAlgorithm() {
        return ALGORITHM;
    }

    public void setAlgorithm(String algorithm) {
        this.ALGORITHM = algorithm;
    }
	public byte[] getCipherText() {
		return cipherText;
	}
	public void setCipherText(byte[] cipherText) {
		this.cipherText = cipherText;
	}
	public byte[] getMac() {
		return mac;
	}
	public void setMac(byte[] mac) {
		this.mac = mac;
	}
	

}

