/**
 * Created by Cody on 5/26/2017.
 */
package iot_security_library;

import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.java.math.BigInteger;
import org.bouncycastle.java.security.SecureRandom;


public class KeyGen {
   
	//128,256, etc
    private  int DEFAULT_KEYLENGTH = 16; //In bytes, default is 128 bit key
    private  String  ELLIPTIC_CURVE = "secp128r1"; //Selected elliptic curve
    private  String DEFAULT_DERIVATION_ALGORITHM = "MD5";
  
    //Users must select curve and the 
    public KeyGen(String ellipticCurve, int secretLengthInBytes) {
    	ELLIPTIC_CURVE = ellipticCurve;
    	DEFAULT_KEYLENGTH = secretLengthInBytes;
	   
   }
    public KeyGen() {
    	ELLIPTIC_CURVE = "secp128r1";
    	DEFAULT_KEYLENGTH = 16;  	
    }

    //Generate a key pair of size 128 bits
   public  AsymmetricCipherKeyPair ECgenerateKeyPair(){

       //Generate parameters based on curve under X9 security standards
       X9ECParameters ecParams = SECNamedCurves.getByName(ELLIPTIC_CURVE);
       

       //Create seed for domain parameters
       Long newLong = (long)(Math.random()* 1000000000);
       Random newRand = new Random(newLong);
       byte [] newBytes = new byte[16];
       newRand.nextBytes(newBytes);

       //Initialize domain paramters
       ECDomainParameters domainParams = new ECDomainParameters(ecParams.getCurve(),ecParams.getG(),ecParams.getN(),ecParams.getH(),newBytes);

       //Generate an EC key pair
       ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
       
       //Seed again for entropy
       SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG", "SUN");
       secRand.setSeed((long)(Math.random()*1000000000));
       ecGen.init(new ECKeyGenerationParameters(domainParams, secRand));

       return ecGen.generateKeyPair();
   }


   //Create secret between two nodes using private key and public key
   public byte [] ECgenerateSecret(AsymmetricKeyParameter privKey, AsymmetricKeyParameter pubKey) throws InvalidKeyException{

       byte [] secret = new byte[DEFAULT_KEYLENGTH];
       ECDHBasicAgreement agreement = new ECDHBasicAgreement();
       agreement.init(privKey);
       BigInteger secretAsInt = agreement.calculateAgreement(pubKey);

       
       byte [] secretAsBytes = secretAsInt.toByteArray();
       if(secretAsBytes.length > DEFAULT_KEYLENGTH) {
    	   
    	   if(secretAsBytes[0] == 0) {
    		   System.arraycopy(secretAsBytes, 1, secret, 0, DEFAULT_KEYLENGTH);
    		   return secret;
    	   } 
    	   else {
    		   throw new InvalidKeyException("Invalid Key Size produced.");
    	   }
       }
       
       System.arraycopy(secretAsBytes, 0, secret, 0, DEFAULT_KEYLENGTH);
       return secret;

   }
   //Public Key Manipulation
   //To byte []
   public static byte [] getPublicKey(AsymmetricKeyParameter pubkey) throws IOException {

       return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubkey).getEncoded();
   }

   //To Asymmetric Key Param
   public static AsymmetricKeyParameter createPublicParamFromKey(byte [] pubkey) throws IOException {

       try {
           return PublicKeyFactory.createKey(pubkey);
       } catch (IOException e) {
           e.printStackTrace();
       }
       return null;
   }

   //Derive a new key based on the generated secret
    public byte [] deriveSymmetricKey(AsymmetricKeyParameter pub1, AsymmetricKeyParameter pub2, byte [] secret) throws NoSuchAlgorithmException, DigestException, IOException {

        MessageDigest hash = MessageDigest.getInstance(DEFAULT_DERIVATION_ALGORITHM);
        hash.update(secret, 0, secret.length);
       
        byte [] key1 = getPublicKey(pub1);
        byte [] key2 = getPublicKey(pub2);
        for(int i = 0; i < key1.length; i ++) {
        	
        	if(key1[i] == key2[i]) {
        		continue;
        	}
        	else if(key1[i] > key2[i]){
                hash.update(key1,0, key1.length);
                hash.update(key2,0, key2.length);
                break;
            }
            else{
                hash.update(key2,0, key2.length);
                hash.update(key1,0, key1.length);
                break;
            }
        }
        
        

        byte[] derivedKey = new byte [DEFAULT_KEYLENGTH];
        hash.digest(derivedKey,0,DEFAULT_KEYLENGTH);
        return derivedKey;
    }
    //Produce a derived key of a desired size
    //**Must be used on both server/client
    public static byte [] deriveSymmetricKey(AsymmetricKeyParameter pub1, AsymmetricKeyParameter pub2, byte [] secret, int keySize, String algorithm) throws NoSuchAlgorithmException, DigestException, IOException {

        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(secret, 0, secret.length);
       
        byte [] key1 = getPublicKey(pub1);
        byte [] key2 = getPublicKey(pub2);

        for(int i = 0; i < key1.length; i ++) {
        	
        	if(key1[i] == key2[i]) {
        		continue;
        	}
        	else if(key1[i] > key2[i]){
                hash.update(key1,0, key1.length);
                hash.update(key2,0, key2.length);
                break;
            }
            else{
                hash.update(key2,0, key2.length);
                hash.update(key1,0, key1.length);
                break;
            }
        }
        

        byte[] derivedKey = new byte [keySize];
        hash.digest(derivedKey,0,keySize);
        return derivedKey;
    }

}
