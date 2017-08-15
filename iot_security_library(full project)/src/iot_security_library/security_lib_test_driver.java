package iot_security_library;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.microedition.io.SocketConnection;
import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.java.security.SecureRandom;

import jdk.dio.gpio.PinEvent;
import jdk.dio.gpio.PinListener;

public class security_lib_test_driver extends MIDlet {

	private static final int FLAME_DETECTOR_PIN = 0;
    private static final int TEMPERATURE_SENSOR_CHANNEL = 0;
	
	public security_lib_test_driver() {
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void destroyApp(boolean unconditional) throws MIDletStateChangeException {
		// TODO Auto-generated method stub

	}

	@Override
	protected void startApp() throws MIDletStateChangeException {
		// TODO Auto-generated method stub
		//System.out.println("Testing Key Generation");
		
		//**TESTING RANDOM NUMBER GENERATION**//
		testSecRand();

        
        //**TEST EC KEY PAIR**//
        AsymmetricCipherKeyPair keyPair = testECKeyGen();
        AsymmetricCipherKeyPair keyPair2 = testECKeyGen();
        AsymmetricCipherKeyPair keyPair3 = testECKeyGen();
    
        try {
			System.out.println("Public Key: " + KeyGen.getPublicKey(keyPair3.getPublic()));
			System.out.println("Public Key Length: " + KeyGen.getPublicKey(keyPair3.getPublic()).length);
			Utility.printFormatedByteArray(KeyGen.getPublicKey(keyPair3.getPublic()));
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

        //**TESTING SECRET GENERATION**//
         byte [] secret = testSecretGeneration(keyPair, keyPair2);

        //**TESTING KEY DERIVATION FORMULA**//
        byte [] derivedSecret = testKeyDerivation(secret, keyPair, keyPair2);

        //**INIT TEST STRING**//
        String test = new String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        System.out.println("Plaintext in bytes: ");
        byte [] testBytes = test.getBytes();
        Utility.printFormatedByteArray(testBytes);
        System.out.println("Plaintext length: " + testBytes.length );


        //**TESTING ENCRYPTION**//
        byte [] cipherText = null;
        byte [] cipherText2 = null;
        try {
			cipherText = testAESEncryption(test, derivedSecret);
			cipherText2 = testAESEncryptionSingleArray(test.getBytes(), derivedSecret);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | ShortBufferException e3) {
			// TODO Auto-generated catch block
			e3.printStackTrace();
		}

        //**TESTING DECRYPTION**//
        byte [] plainText = null;
        byte [] plainText2 = null;
        try {
			plainText = testAESDecryption(cipherText, derivedSecret);
			plainText2 = testAESDecryptionSingleArray(cipherText2, derivedSecret);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | ShortBufferException e3) {
			// TODO Auto-generated catch block
			e3.printStackTrace();
		}
        String plainTextOutput = new String(plainText);
        System.out.println("Plain text as string: " + plainTextOutput);
//        
//        
        //**TESTING HMACS**//
        Authentication authen = new Authentication();
        byte [] mac = null;
        try {
			mac = authen.createHMAC(new MD5Digest(),cipherText , derivedSecret);
			authen.verifyHMAC(new MD5Digest(), mac, cipherText, derivedSecret);
		} catch (ShortBufferException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        byte[] mac2;
		try {
			mac2 = authen.createHMAC128(cipherText , derivedSecret);
			authen.verifyHMac128(mac2, cipherText, derivedSecret);
			authen.encryptAndMAC(plainText, derivedSecret);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
        //**TESTING GCM ENCRYPTION**//
		byte [] nonce = Encryption.generateNonce();
        byte [] gcmCipherText = testGCMEncryption(derivedSecret, testBytes, "AAD TEST".getBytes(), nonce);
        
        
        //**TESTING GCM DECRYPT
        //byte [] gcmPlaintext = testGCMDecryption(derivedSecret, gcmCipherText, nonce);
        
      
        //**TEST FLAME SENSOR**//  
        //testFlameSensor();
      
        
        
       //**TEST SERVER**//
//        try {
//			testServer(4040,"NUL");
//		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
//				| BadPaddingException | ShortBufferException | InvalidCipherTextException | DigestException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
//        //**END SERVER TEST**//
//        
       //**TEST CLIENT**// 
//        try {
//			testClient();
//		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
//				| BadPaddingException | ShortBufferException | InvalidCipherTextException | DigestException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
        //**END CLIENT TEST**//
        
        //**TEST MESSAGE GCM**//
        //testGCMMessage();

        //**TESTING TEMPERATURE SENSOR**//
        //testTempSensor();
       
        //** TEST EXECUTION TIME**//
        
        
        float [] averageTimes = new float[9];
        int numExecutions = 1000;
        int payloadSize = 16;//bytes
        byte [] payload = new byte[payloadSize];
        for(int i = 0; i < payloadSize; i++) {
        	payload[i]= (byte)'A';
        	
        }
        Utility.printFormatedByteArray(payload);
        
        
      //Test key generation
        for(int i = 0; i < numExecutions; i++) {
        	averageTimes[0] += testTimeKeyGen();
        	System.out.println("Iteration: "+ i);
        	
        }
        float value = averageTimes[0]/numExecutions;
        averageTimes[0] = value;
        
        
        //Test Secret Gen
        try {
			
			for(int i = 0; i < numExecutions; i++) {
	
				averageTimes[1] += testSecretGen(keyPair, keyPair2);;
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[1]/numExecutions;
	        averageTimes[1] = value;
	        
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //Test Key Derivation
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				averageTimes[2] += testKeyDerivation(keyPair,keyPair2, secret);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[2]/numExecutions;
	        averageTimes[2] = value;
	        
		} catch (NoSuchAlgorithmException | DigestException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //Test AES encryption time
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				averageTimes[3] += testAESEncryptionTime(payload, derivedSecret);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[3]/numExecutions;
	        averageTimes[3] = value;
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      //Test AES decryption time
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				averageTimes[4] += testAESDecryptionTime(cipherText, derivedSecret);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[4]/numExecutions;
	        averageTimes[4] = value;
	        
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        //Test GCM encryption
        byte [] nonceTest = Encryption.generateNonce();
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				
				averageTimes[5] += testGCMEncryptionTime(derivedSecret, payload, payload, nonceTest);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[5]/numExecutions;
	        averageTimes[5] = value;
			
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      //Test GCM decryption
        Encryption encrypt = new Encryption();
        
        try {
			gcmCipherText = encrypt.gcmEncrypt(derivedSecret, payload,payload, nonceTest );
		} catch (InvalidCipherTextException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				Utility.printFormatedByteArray(encrypt.cipherText);
				Utility.printFormatedByteArray(encrypt.mac);
				averageTimes[6] += testGCMDecryption(derivedSecret, gcmCipherText, payload, nonceTest);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[6]/numExecutions;
	        averageTimes[6] = value;
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //Test HMAC speed
        try {
			
			for(int i = 0; i < numExecutions; i++) {
				averageTimes[7] += testHMACTime(cipherText,derivedSecret);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[7]/numExecutions;
	        averageTimes[7] = value;
	        //Reformat
	        //averageTimes[7] = (float)Math.round((averageTimes[7]*100000000))/1000000;
	        
	        for(int i = 0; i < numExecutions; i++) {
	        	averageTimes[8] += testHMACVerify(mac, cipherText, derivedSecret);
	        	System.out.println("Iteration: "+ i);
	        }
	        value = averageTimes[8]/numExecutions;
	        averageTimes[8] = value;
			
		} catch (InvalidCipherTextException | ShortBufferException | InvalidKeyException e) {
			
			e.printStackTrace();
		}
         
        
       
        System.out.println("Average function speed in milliseconds for payload size: " + payload.length + " bytes");
        System.out.println("EC Key pair generation average Time: | "+ averageTimes[0] + " ms");
        System.out.println("ECDH secret generation average Time: | "+ averageTimes[1] + " ms");
        System.out.println("Key derivation average Time:         | "+ averageTimes[2] + " ms");
        System.out.println("AES encryption average Time:         | "+ averageTimes[3] + " ms");
        System.out.println("AES decryption average Time:         | "+ averageTimes[4] + " ms");
        System.out.println("GCM encryption average Time:         | "+ averageTimes[5] + " ms");
        System.out.println("GCM decryption average Time:         | "+ averageTimes[6] + " ms");
        System.out.println("HMAC MD5 generation average Time:    | " + averageTimes[7] + " ms");
        System.out.println("HMAC MD5 verify average Time:        | "+ averageTimes[8] + " ms");
       
//		//**TEST FIRE DETECTION AS CLIENT**//
//        FireDetectionSystem detectFlames = new FireDetectionSystem();
//        try {
//        	System.out.println("Detecting fire...");
//			detectFlames.runDetection("NUL");
//		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
//				| BadPaddingException | ShortBufferException | InvalidCipherTextException | DigestException
//				| IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//        //**TEST FIRE DETECTION AS SERVER**//
//        FireDetectionSystem serverWait = new FireDetectionSystem();
//        try {
//        	System.out.println("Awaiting Message....");
//			serverWait.serverAwaitDetection(4040, "NUL");
//		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
//				| BadPaddingException | ShortBufferException | InvalidCipherTextException | DigestException
//				| IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

	}
	
	
	/*
	 * TEST FUNCTIONS
	 */
	public void testSecRand() {
		Long newLong = (long)(Math.random()* 1000000000);
        System.out.println(newLong);
        Random newRand = new Random(newLong);
        byte [] newBytes = new byte[16];
        newRand.nextBytes(newBytes);

        SecureRandom newSecRand = new SecureRandom(newBytes);
        System.out.println("Sec Rand: " + newSecRand.nextInt());
	}
	//TESTING EC KEY GEN
	public AsymmetricCipherKeyPair testECKeyGen() {
		 KeyGen keyGenerator = new KeyGen("secp128r1", 16);
	        AsymmetricCipherKeyPair keyPair = keyGenerator.ECgenerateKeyPair();
	        System.out.println("\nTesting EC Key Pair Generation One...");
	        System.out.println("Private Key: " + keyPair.getPrivate());
	        System.out.println("Public Key: " + keyPair.getPublic());
	        return keyPair;
	}
	//TEST SECRET GENERATION
	public byte [] testSecretGeneration(AsymmetricCipherKeyPair keyPair,AsymmetricCipherKeyPair keyPair2 ) {
		System.out.println("\nTesting Secret Generation...");
		KeyGen keyGen = new KeyGen();
		
        byte[] secret = null;
		try {
			secret = keyGen.ECgenerateSecret(keyPair.getPrivate(),keyPair2.getPublic());
			byte [] secret2 = keyGen.ECgenerateSecret(keyPair2.getPrivate(), keyPair.getPublic());
			 System.out.println("Secret: ");
	          Utility.printFormatedByteArray(secret);
	          System.out.println("Secret2: ");
	          Utility.printFormatedByteArray(secret2);
	          System.out.println("Secret length: " + secret.length);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return secret;
	}
	//TEST KEY DERIVATION
	public byte [] testKeyDerivation(byte [] secret, AsymmetricCipherKeyPair keyPair,AsymmetricCipherKeyPair keyPair2) {
		System.out.println("\nTesting Key Derivation...");
        System.out.println("Previous Key: ");
        Utility.printFormatedByteArray(secret);
        System.out.println("Derived Key: ");
        byte [] derivedSecret = null;
        try {
            derivedSecret = KeyGen.deriveSymmetricKey(keyPair.getPublic(),keyPair2.getPublic(),secret, 16, "MD5");
        } catch (NoSuchAlgorithmException ex) {
        } catch (DigestException ex) {
        } catch (IOException ex) {
        }
        System.out.println("Derived Secret: ");
        Utility.printFormatedByteArray(derivedSecret);
        return derivedSecret;
	}
	//TEST AES ENCRYPTION
	public byte [] testAESEncryption(String test, byte[] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		System.out.println("Encrypted: ");
        byte [] cipherText = null;
        Encryption encrypter = new Encryption();
        cipherText = encrypter.encrypt(test.getBytes(), derivedSecret);
        Utility.printFormatedByteArray(cipherText);
        return cipherText;
	}
	public byte [] testAESEncryptionSingleArray(byte [] test, byte[] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		System.out.println("Encrypted: ");
        byte [] cipherText = null;
        Encryption encrypter = new Encryption();
        byte [] finalOutput = new byte [test.length + derivedSecret.length];
    	System.arraycopy(test, 0, finalOutput, 0, test.length);
		System.arraycopy(derivedSecret, 0, finalOutput, test.length, derivedSecret.length);
        cipherText = encrypter.encrypt(finalOutput, test.length, derivedSecret.length, 0, test.length);
        Utility.printFormatedByteArray(cipherText);
        return cipherText;
	}
	//TEST AES DECRYPTION
	public byte [] testAESDecryption(byte [] cipherText, byte[] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		System.out.println("Decrypted: ");
        Encryption encrypter = new Encryption();
        byte [] plainText = encrypter.decrypt(cipherText, derivedSecret);
        Utility.printFormatedByteArray(plainText);
        return plainText;
	}
	public byte [] testAESDecryptionSingleArray(byte [] cipherText, byte[] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		System.out.println("Decrypted: ");
        Encryption encrypter = new Encryption();
        byte [] finalOutput = new byte [cipherText.length + derivedSecret.length];
    	System.arraycopy(cipherText, 0, finalOutput, 0, cipherText.length);
		System.arraycopy(derivedSecret, 0, finalOutput, cipherText.length, derivedSecret.length);
        byte [] plainText = encrypter.decrypt(finalOutput, cipherText.length, derivedSecret.length, 0, cipherText.length );
        Utility.printFormatedByteArray(plainText);
        return plainText;
	}
	//TEST GCM ENCRYPTION
	public byte [] testGCMEncryption(byte [] derivedSecret,byte[] gcmTest, byte[] testAAD, byte [] nonce) {
		
		Encryption encrypter = new Encryption();
		
        
        byte [] gcmCipherText = null;
        try {
            gcmCipherText = encrypter.gcmEncrypt(derivedSecret, gcmTest,testAAD, nonce );
        } catch (InvalidCipherTextException ex) {
            
        }
        System.out.println("GCM INPUT: ");
        Utility.printFormatedByteArray(gcmTest);
        String inputAsString = new String(gcmTest);
        System.out.println("Input: ");
        System.out.println(inputAsString);
        System.out.println("Encrypted GCM: ");
        Utility.printFormatedByteArray(gcmCipherText);
        
        byte [] testOutput = new byte[encrypter.cipherText.length + encrypter.getMac().length];
        
        System.arraycopy(encrypter.cipherText,0, testOutput, 0, encrypter.cipherText.length);
        System.arraycopy(encrypter.getMac(),0, testOutput, encrypter.cipherText.length, encrypter.getMac().length);
        System.out.println("Concatonated: ");
        Utility.printFormatedByteArray(testOutput);
        System.out.println("Original output buffer: ");
        Utility.printFormatedByteArray(gcmCipherText);
        
        return gcmCipherText;
	}
	//TEST GCM DECRYPTION
	public byte [] testGCMDecryption(byte[] derivedSecret, byte[] gcmCipherText, byte [] nonce) {
		System.out.println("Decrypted GCM: ");
		Encryption encrypter = new Encryption();
        byte [] gcmPlainText = null;
        try {
            gcmPlainText = encrypter.gcmDecrypt(derivedSecret, gcmCipherText, "AAD TEST".getBytes(), nonce);
        } catch (InvalidCipherTextException ex) {
            
        }
        Utility.printFormatedByteArray(gcmPlainText);
        return gcmPlainText;
	}
	public void testHMAC(byte[] cipherText, byte[] derivedSecret) {
		Authentication authen = new Authentication();
        byte [] mac = null;
        try {
			mac = authen.createHMAC(new MD5Digest(),cipherText , derivedSecret);
			authen.verifyHMAC(new MD5Digest(), mac, cipherText, derivedSecret);
		} catch (ShortBufferException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	//Flame sensor
	public void testFlameSensor() {
      FlameSensor flame = null;
      try {
			flame = new FlameSensor(FLAME_DETECTOR_PIN);
			System.out.println("Flame sensor created..");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
      try {
			flame.setListener(new FlameDetector());
			System.out.println("Listener set...");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
      for(int i = 0; i < 10; i++){
      	
      	System.out.println("No flames detected....");
      	
      	try {
				System.out.println("Flame data value: " + flame.getData());
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
      	
      	 try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}      	
      }
	}
	//Test Temperature Sensor
	public void testTempSensor() {
      TemperatureSensor tempSensor = null;
      System.out.println("Starting temperature sensors..");
      try {
			tempSensor = new TemperatureSensor(TEMPERATURE_SENSOR_CHANNEL);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      System.out.println(tempSensor.convertTemp(2200));
      System.out.println(tempSensor.log(16.0)/tempSensor.log(10));
	   //System.out.println("Value: "+ tempSensor.byteArrayToInt(Utility.hexStringToByteArray("32313238")));
	   try {
		System.out.println(tempSensor.convertTemp(Integer.parseInt(new String(Utility.hexStringToByteArray("32313238"), "UTF-8"))));
		   
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

     try {
  	   System.out.println("File Read: " + tempSensor.getTemp());
		//printFormatedByteArray(tempSensor.readFile());
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	}
	
	
	//Server
	public void testServer(int port, String encryptScheme) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
      System.out.println("Creating Server and listening...");
      
      
      try {
			Server server = new Server(port, encryptScheme);
			server.start();
			server.receiveAndProcess(1024);
			server.sendMessage("Hello World!".getBytes(), "Extra Data".getBytes());
			server.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	//Test Client
	public void testClient() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
      System.out.println("Creating client...");
      System.out.println("Connecting to server...");
      try {
			Client client = new Client("127.0.0.1", 4040, "GCM");
			client.start();
			//client.sendMessage("Hello World!".getBytes(), "ExtraData".getBytes());
			client.sendKey();
			client.receiveAndProcess(1024);
			client.close();
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	//Test GCM Message
	public void testGCMMessage(){
      
	 Encryption encrypter = new Encryption();
		
	  Message msg = new Message("MSG", "GCM", "AAAAAAAAAAAAAAA".getBytes(), "AAD TEST".getBytes(), encrypter.getMac(), Encryption.generateNonce());
      
      System.out.println("Message type: ");
      Utility.printFormatedByteArray(msg.getMsgType());
      System.out.println("Encryption type: ");
      Utility.printFormatedByteArray(msg.getEncryptScheme());
      System.out.println("Message length: ");
      Utility.printFormatedByteArray(Utility.convertShortToByte(msg.getMsgLength()));
      //System.out.println("Message length as short: ");
      //System.out.println(msg.convertByteToShort(msg.convertShortToByte(msg.getMsgLength())));
      System.out.println("MAC length: ");
      Utility.printFormatedByteArray(Utility.convertShortToByte(msg.getMacLength()));
      System.out.println("AAD length: ");
      Utility.printFormatedByteArray(Utility.convertShortToByte(msg.getAdditionalDataLength()));
      
      System.out.println("Message: ");
      Utility.printFormatedByteArray(msg.getMessage());
      System.out.println("MAC: ");
      Utility.printFormatedByteArray(msg.getMac());
      System.out.println("Additional Data: ");
      Utility.printFormatedByteArray(msg.getAdditionalData());
      System.out.println("Nonce: ");
      Utility.printFormatedByteArray(msg.getNonce());
      
      System.out.println("Final message: ");
      try {
      	byte [] finalMessage = msg.createMessage();
			Utility.printFormatedByteArray(finalMessage);
			Server serv = new Server(4040, "GCM");
	        Message parsedMessage = serv.parseMessage(finalMessage);
	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 * TEST EXECUTION TIMES
	 */
	
	public float testTimeKeyGen() {
		KeyGen keyGenerator = new KeyGen("secp128r1", 16);
		//Init
		AsymmetricCipherKeyPair keyPair = keyGenerator.ECgenerateKeyPair();
		//Test speed
		long startTime = System.nanoTime();
		AsymmetricCipherKeyPair keyPair2 = keyGenerator.ECgenerateKeyPair();
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("Key generation time:" + totalTime);
		return totalTime;
		
	}
	public float testSecretGen(AsymmetricCipherKeyPair keyPair,AsymmetricCipherKeyPair keyPair2) throws InvalidKeyException {
		
		KeyGen keyGenerator = new KeyGen("secp128r1", 16);
		//Init
		keyGenerator.ECgenerateSecret(keyPair.getPrivate(),keyPair2.getPublic());
		
		//Test Time
		long startTime = System.nanoTime();
		keyGenerator.ECgenerateSecret(keyPair.getPrivate(),keyPair2.getPublic());
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("Secret generation time:" + totalTime);
		return totalTime;
		
		
	}
	public float testKeyDerivation(AsymmetricCipherKeyPair keyPair,AsymmetricCipherKeyPair keyPair2, byte [] secret) throws NoSuchAlgorithmException, DigestException, IOException {
		
		KeyGen.deriveSymmetricKey(keyPair.getPublic(),keyPair2.getPublic(),secret, 16, "MD5");
		
		long startTime = System.nanoTime();
		KeyGen.deriveSymmetricKey(keyPair.getPublic(),keyPair2.getPublic(),secret, 16, "MD5");
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("Key derivation time:" + totalTime);
		return totalTime;
	}
	
	public float testAESEncryptionTime(byte [] test, byte [] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		
		Encryption encrypter = new Encryption();
		
		//Init
		encrypter.encrypt(test, derivedSecret);
		
		//Time
		long startTime = System.nanoTime();
		encrypter.encrypt(test, derivedSecret);
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("AES encryption time:" + totalTime);
		return totalTime;
	}
	public float testAESDecryptionTime(byte [] cipherTest, byte [] derivedSecret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		
		Encryption encrypter = new Encryption();
		
		//Init
		encrypter.encrypt(cipherTest, derivedSecret);
		
		//Time
		long startTime = System.nanoTime();
		encrypter.decrypt(cipherTest, derivedSecret);
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("AES Decryption time:" + totalTime);
		return totalTime;
	}
	public float testGCMEncryptionTime(byte[] derivedSecret,byte[] testBytes,byte[] testAAD, byte[] nonce) throws InvalidCipherTextException {
		
		Encryption encrypter = new Encryption();
		
		//Init
		encrypter.gcmEncrypt(derivedSecret, testBytes ,testAAD, nonce );
		//Test Time
		long startTime = System.nanoTime();
		encrypter.gcmEncrypt(derivedSecret, testBytes ,testAAD, nonce );
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("GCM encryption time:" + totalTime);
		return totalTime;
	}
	public float testGCMDecryption(byte[] derivedSecret,byte[] testBytes,byte[] testAAD, byte[] nonce) throws InvalidCipherTextException {
		
		Encryption encrypter = new Encryption();
		
		//Init
		encrypter.gcmDecrypt(derivedSecret, testBytes ,testAAD, nonce );
		//Test Time
		long startTime = System.nanoTime();
		encrypter.gcmDecrypt(derivedSecret, testBytes ,testAAD, nonce );
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("GCM decryption time:" + totalTime);
		return totalTime;
	}
	public float testHMACTime(byte []data, byte[] key) throws InvalidCipherTextException, ShortBufferException {
		
		Authentication authen = new Authentication();
	
		//Init
		byte[] mac = authen.createHMAC(new MD5Digest(), data, key);
		//Test Time
		long startTime = System.nanoTime();
		authen.createHMAC(new MD5Digest(), data, key);
		long endTime = System.nanoTime();
		Utility.printFormatedByteArray(mac);
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("MAC generation time:" + totalTime);
		return totalTime;
	}
	public float testHMACVerify(byte []data, byte[] key, byte[] mac) throws InvalidCipherTextException, ShortBufferException, InvalidKeyException {
		
		Authentication authen = new Authentication();
		
		//Init
		authen.verifyHMAC(new MD5Digest(), mac, data, key);
		//Test Time
		long startTime = System.nanoTime();
		authen.verifyHMAC(new MD5Digest(), mac,  data, key);
		long endTime = System.nanoTime();
		float totalTime = (float)(endTime-startTime)/1000000;
		System.out.println("MAC verify time:" + totalTime);
		return totalTime;
	}
	
	


}
