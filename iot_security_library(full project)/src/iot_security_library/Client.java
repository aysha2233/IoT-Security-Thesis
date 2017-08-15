package iot_security_library;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.microedition.io.Connector;
import javax.microedition.io.ServerSocketConnection;
import javax.microedition.io.SocketConnection;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class Client {
	
	//**Private Vars**//
	private SocketConnection clientConnection = null;
	private DataOutputStream os = null;
	private DataInputStream is = null;
    private static final int DEFAULT_KEY_LENGTH = 128; //Default is 128 bit key
	
	//Protocol vars
	private String encryptType = "NUL"; //encryption scheme being used
	private byte [] key = null; //Shared Secret, possibly change to array to support multiple connections
	private AsymmetricCipherKeyPair keyPair = null; //Servers key pair
	private AsymmetricKeyParameter serverPub = null;

	//**Public Functions**//
	
	//**Constructors**//
	public Client(String hostname, int port, String encryptType) throws IOException {
		clientConnection = (SocketConnection) Connector.open("socket://" + hostname + ":"+port);
		this.encryptType = encryptType;
	}
	public Client(SocketConnection newConnection) {
		this.clientConnection = newConnection;
	}
	public Client() {
		
	}
	
	//**Utility
	public void start() throws IOException {
		os = clientConnection.openDataOutputStream();
	}
	
	public void start(byte [] message) throws IOException {
		os = clientConnection.openDataOutputStream();
		sendDataRaw(message);
	}
	
	public void close() throws IOException {
		if(clientConnection == null || os == null) {
			return;
		}
		clientConnection.close();
		os.close();
		this.is.close();
        this.is = null;
	}
    public boolean sendDataRaw(byte [] message) {
    	
    	if(os != null) {
	    	try {
				os.write(message);
				return true;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    	return false;
    }
    public boolean sendMessage(byte [] message, byte[] extraData) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException {
    	
    	if(os != null){
    		if(encryptType.equals("NUL")){
    			
    			Message newMessage = new Message("MSG", encryptType, message);
			   	    			
    			try{
					os.write(newMessage.createMessage());
					return true;
				} catch (IOException e) {
					e.printStackTrace();
				}
    		}
    		else if(encryptType.equals("AES")) {
    			
    			
    			if(key != null) {
    				Encryption encrypter = new Encryption();
    				
    				byte [] cipherText = encrypter.encrypt(message, this.key);
    				byte [] hmac = Authentication.createHMAC128(cipherText, this.key);
    				
    				Message newMessage = new Message("MSG", encryptType, cipherText, extraData, hmac);
    				
    				try{
						os.write(newMessage.createMessage());
						return true;
					} catch (IOException e) {
						
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
    			}
    			else {
    				throw new IllegalArgumentException("Missing a key for encryption.");
    			}
    		}
    		else if(encryptType.equals("GCM")) {
    			
    			if(key != null) {
    				Encryption encryptor = new Encryption();
    				byte [] nonce = encryptor.generateNonce();
    				encryptor.gcmEncrypt(key, message, extraData, nonce);

    				Message newMessage = new Message("MSG", encryptType,  encryptor.getCipherText(), extraData, encryptor.getMac(), nonce);
    				
    				try{
						os.write(newMessage.createMessage());
						return true;
					} catch (IOException e) {
						
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
    			}
    		}
    	}
    	return false;
    }
    public boolean sendKey() throws IOException, InvalidKeyException {
		 
    	if(this.getKeyPair() != null) {
			 byte [] pubkey = KeyGen.getPublicKey(this.keyPair.getPublic());
			
			 
			 Message newMessage = new Message("KEY", pubkey);
   			System.out.println("Sending public key from key pair..");
			 try{
				 os.write(newMessage.createMessage());
				 return true;
				} catch (IOException e) {
					e.printStackTrace();
				}
			 
		 }
		 else {
			KeyGen keygen = new KeyGen();
			System.out.println("Creating ephemeral key pair...");
			this.keyPair = keygen.ECgenerateKeyPair();
			byte [] pubkey = KeyGen.getPublicKey(this.getKeyPair().getPublic());
			 
			 Message newMessage = new Message("KEY", pubkey);
  			
			 try{
				 os.write(newMessage.createMessage());
				 return true;
				} catch (IOException e) {
					e.printStackTrace();
				}
		 }
		 return false;
	 }
    
    public byte [] receiveDataRaw(int maxReceiveSize) throws IOException {
    	if(this.is == null) {
			try {
				is = clientConnection.openDataInputStream();
			} catch (IOException e) {
				e.printStackTrace();
			}
    	}
    	byte [] received = new byte [maxReceiveSize];
    	
    	//Read bytes from data stream
        int bytesRead = 0;
        
		try {
			bytesRead = is.read(received);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if(received.length < 3) {
    		close();
    		return received;
    	}
        if(bytesRead > maxReceiveSize){
        	System.out.println("Data read exceeded input buffer, some data may have been lost");
        }
        System.out.println("Bytes read: " + bytesRead);
       
        //Close In-stream
//        this.is.close();
//        this.is = null;
        
    	return received;
    }
    
    public Message receiveAndProcess(int maxReceiveSize) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
		
		//Receive data over the network
		byte [] receivedData = receiveDataRaw(maxReceiveSize);
		//Parse data into message object
		if(receivedData.length < 4) {
			return new Message();
		}
		Message msg = parseMessage(receivedData);
		
		
		//Determine message type: key exchange or general message
		String msgType = new String(msg.getMsgType());
		
		// TODO: KEY EXCHANGE
		if(msgType.equals("KEY")) {
			if(key == null) {
				
				//Processes the new key and creates new derived key
				processKey(msg);
			}
			else {
				throw new InvalidKeyException("Key already initialized.");
			}
		}
		else if(msgType.equals("MSG")) {
			
			//Determine type of encryption used
			this.setEncryptType(new String(msg.encryptScheme));
			
			
			//Validate and decrypt for AES scheme
			if(encryptType.equals("AES")) {
				 return processAES(msg);
			}
			//Validate and decrypt for GCM scheme
			else if(encryptType.equals("GCM")){
				return processGCM(msg);
			}
		}
		return msg;
	}
    
    public Message parseMessage(byte [] fullMessage) {
		 Message msg = new Message();
		 int offset = 0;
		 
		 msg.setMsgType(Arrays.copyOfRange(fullMessage, offset, offset+=3));
		 //msg.printFormatedByteArray(msg.getMsgType());
		 
		 String msgTypeStr = new String(msg.getMsgType());
		 
		 if(msgTypeStr.equals("MSG") || msgTypeStr.equals("KEY")) {
			
			 
			 msg.setEncrypScheme(Arrays.copyOfRange(fullMessage, offset, offset+=3));
			 
			 //msg.printFormatedByteArray(msg.getEncryptScheme());
			 String encryptScheme = new String(msg.getEncryptScheme());
			 
			 if(encryptScheme.equals("NUL") || encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
				 msg.setMsgLength(Utility.convertByteToShort(Arrays.copyOfRange(fullMessage, offset, offset+=2)));
				 //System.out.println(msg.getMsgLength());
				 
				 msg.setMacLength(Utility.convertByteToShort(Arrays.copyOfRange(fullMessage, offset, offset+=2)));
				 //System.out.println(msg.getMacLength());
				 
				 msg.setAdditionalDataLength(Utility.convertByteToShort(Arrays.copyOfRange(fullMessage, offset, offset+=2)));
				 //System.out.println(msg.getAdditionalDataLength());
				 
				 msg.setNonceLength(Utility.convertByteToShort(Arrays.copyOfRange(fullMessage, offset, offset+=2)));
				 //System.out.println(msg.getAdditionalDataLength());

				 msg.setMessage(Arrays.copyOfRange(fullMessage, offset, offset+=msg.getMsgLength()));
				 //msg.printFormatedByteArray(msg.getMessage());
				 
				 msg.setMac(Arrays.copyOfRange(fullMessage, offset, offset+=msg.getMacLength()));
				 //msg.printFormatedByteArray(msg.getMac());
				 
				 msg.setAdditionalData(Arrays.copyOfRange(fullMessage, offset, offset+=msg.getAdditionalDataLength()));
				 //msg.printFormatedByteArray(msg.getAdditionalData());
				 
				 msg.setNonce(Arrays.copyOfRange(fullMessage, offset, offset+=msg.getNonceLength()));
				 //msg.printFormatedByteArray(msg.getNonce());
			 }
			 else {
				 throw new IllegalArgumentException("Invalid encryption scheme");
			 } 
		 }
		 else {
			 throw new IllegalArgumentException("Invalid message type received.");
		 }		
		 return msg;
	 }
    
    public void processKey(Message msg) throws IOException, NoSuchAlgorithmException, DigestException, InvalidKeyException {
		
		 //Convert bytes to key param 
		 byte [] clientkey = msg.getMessage();
		 
		 this.setServerPub(KeyGen.createPublicParamFromKey(clientkey));
		 KeyGen keyGen = new KeyGen();
 
		 //Generate secret key
		 this.setKey(keyGen.ECgenerateSecret(this.keyPair.getPrivate(), this.getServerPub()));	
		
		 //Derive key
		 byte [] derivedKey = keyGen.deriveSymmetricKey(this.keyPair.getPublic(), this.getServerPub(), this.getKey());
		 
		 this.setKey(derivedKey);
		
	 }
    
  //Authenticate and decrypt message for AES encryption method
  	 private Message processAES(Message msg) throws InvalidKeyException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
  		
  		 Encryption decrypter = new Encryption();
  		 
  		 if(this.key != null) {
  				String mac = new String(msg.getMac());
  				//Validate MAC
  				if(!mac.equals("null")) {
  					if(Authentication.verifyHMAC(msg.getMac(), msg.getMessage(),key, new MD5Digest())){	
  						//Decrypt cipher text
  						byte [] plainText = decrypter.decrypt(msg.getMessage(), key);
  						msg.setMessage(plainText);
  						
  					} 
  					else {
  						throw new IllegalArgumentException("Invalid MAC, message authentication failed.");
  					}
  				}
  				else {
  					
  					byte [] plainText = decrypter.decrypt(msg.getMessage(), key);
  					msg.setMessage(plainText);
  					System.out.println("WARNING: Message not authenticated.");
  				}
  			}
  			else {
  				throw new IllegalArgumentException("No key established.");
  			}
  		 return msg;
  	 }
  	 
  	 
  	 //Authenticate and decrypt GCM
  	 private Message processGCM(Message msg) throws InvalidCipherTextException {
  		 
  		 Encryption decrypter = new Encryption();
  		 
  		 if(this.key != null) {
  			 
  			byte [] cipherAndTag = new byte [msg.macLength+msg.msgLength];
			 System.arraycopy(msg.getMessage(), 0, cipherAndTag, 0, msg.getMsgLength());
			 System.arraycopy(msg.getMac(), 0, cipherAndTag, msg.getMsgLength(), msg.getMacLength());
			 System.out.println("Received Nonce (Client): ");
			 Utility.printFormatedByteArray(msg.getNonce());
			 System.out.println("Received Ciphertext + Tag (Client): ");
			 Utility.printFormatedByteArray(cipherAndTag);
			 //msg.setMessage(decrypter.gcmDecrypt(this.key, msg.getMessage(), msg.getAdditionalData(), msg.getNonce()));
			 System.out.println("Received AAD:(Client) ");
			Utility.printFormatedByteArray(msg.getAdditionalData());
			System.out.println("This key: (Client)");
			 Utility.printFormatedByteArray(this.key);
			 
			 msg.setMessage(decrypter.gcmDecrypt(this.key, cipherAndTag, msg.getAdditionalData(), msg.getNonce()));

			 if(msg.getMessage() == null) {
				throw new InvalidCipherTextException("Invalid MAC, message authentication failed.");
			 }
  		 }
  			
  		return msg;
  	 }
	
	//*Getters & Setters**//
	public SocketConnection getClientConnection() {
		return clientConnection;
	}

	public void setClientConnection(SocketConnection clientConnection) {
		this.clientConnection = clientConnection;
	}
	public void setEncryptType(String encryptType) {
		this.encryptType = encryptType;
	}
	public byte[] getKey() {
		return key;
	}
	public void setKey(byte[] key) {
		this.key = key;
	}
	public AsymmetricCipherKeyPair getKeyPair() {
		return this.keyPair;
	}
	public void setKeyPair(AsymmetricCipherKeyPair keyPair) {
		this.keyPair = keyPair;
	}
	public AsymmetricKeyParameter getServerPub() {
		return serverPub;
	}
	public DataOutputStream getOs() {
		return os;
	}
	public void setOs(DataOutputStream os) {
		this.os = os;
	}
	public DataInputStream getIs() {
		return is;
	}
	public void setIs(DataInputStream is) {
		this.is = is;
	}
	public void setServerPub(AsymmetricKeyParameter serverPub) {
		this.serverPub = serverPub;
	}
	public static int getDefaultKeyLength() {
		return DEFAULT_KEY_LENGTH;
	}
	public String getEncryptType() {
		return encryptType;
	}
	
	

}
