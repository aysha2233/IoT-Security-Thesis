
package iot_security_library;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Created by Cody on 5/31/2017.
 */
public class Authentication {

    private static final String DEFAULT_HASH_ALGORITHM = "MD5";
    public int macLength = 0;

    //Default HMAC, expects 128 key using MD5
    public static byte [] createHMAC128(byte [] data, byte [] key) throws InvalidKeyException {

        if(key.length != 16){
            throw new InvalidKeyException();
        }
        byte [] completedMAC = new byte[16];
        HMac newMAC = new HMac(new MD5Digest());

        newMAC.init(new KeyParameter(key));
        newMAC.update(data, 0, data.length);
        newMAC.doFinal(completedMAC, 0);
        
        return completedMAC;
    }
   
    
    //Default verify HMAC, computes HMAC and compares to the recieved HMAC
    //Expects 128 bit key
    public static boolean verifyHMac128(byte [] recievedMac, byte[] data, byte[] key ) throws InvalidKeyException {
        return Arrays.areEqual(createHMAC128(data, key), recievedMac);
    }

    public static byte [] createHMAC(GeneralDigest digest, byte [] data, byte [] key) throws ShortBufferException {

        int keyLength = key.length;
        int blockSize = digest.getDigestSize();
        byte [] keyUpdated = new byte[blockSize];
        HMac newMAC = new HMac(digest);
        byte [] completedMAC = new byte[newMAC.getMacSize()];

        //Configure Key to correct size
        if(keyLength > blockSize ){
            digest.update(key,0,keyLength);
            digest.doFinal(keyUpdated,0);
            newMAC.init(new KeyParameter(keyUpdated));
        }
        else if(keyLength < blockSize){

            System.arraycopy(key,0,keyUpdated,0, keyLength);
            for( int i = keyLength; i < (blockSize - keyLength); i++){
                keyUpdated[i] = 0;
            }
            newMAC.init(new KeyParameter(keyUpdated));
        }
        else{
            newMAC.init(new KeyParameter(key));
        }

        newMAC.update(data, 0, data.length);
        newMAC.doFinal(completedMAC, 0);
        return completedMAC;
    }

    public static boolean verifyHMAC(GeneralDigest digest, byte [] recievedMac, byte[] data, byte[] key ) throws InvalidKeyException, ShortBufferException {
        return Arrays.areEqual(createHMAC(digest,data, key), recievedMac);
    }
    
    //Quick and easy for returning ciphertext + mac
    // Mac size is 128 
    public static byte[] encryptAndMAC(byte [] plainText, byte [] key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    	
    	if(key.length != 16) {
    		throw new InvalidKeyException("Invalid key size");
    	}
    	Encryption encrypt = new Encryption();
    	byte [] cipherText = encrypt.encrypt(plainText, key);
    	byte [] mac = createHMAC128(cipherText, key);
    	byte [] finalOutput = new byte [cipherText.length + mac.length];
    	System.arraycopy(cipherText, 0, finalOutput, 0, cipherText.length);
		System.arraycopy(mac, 0, finalOutput, cipherText.length, mac.length);
		return finalOutput;
    	
    	
    	
    }


}
