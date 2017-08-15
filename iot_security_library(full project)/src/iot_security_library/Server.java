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

public class Server {
	
	//**Private Vars**//
    private static final int DEFAULT_KEY_LENGTH = 16; //Default is 128 bit key
	private ServerSocketConnection serverConnection = null;
	private Client client = null; //Possibly change to array for multiple connections
	private DataOutputStream os = null;
	private DataInputStream is = null;
	
	
	//Protocol vars
	private String encryptType = "NUL"; //encryption scheme being used
	private byte [] key = null; //Shared Secret, possibly change to array to support multiple connections
	private AsymmetricCipherKeyPair keyPair = null; //Servers key pair
	private AsymmetricKeyParameter clientPub = null;
	
	
	//**Public Functions**//
	//Encryption schemes: GCM, AES, NONE
	public Server(int port, String encryptScheme) throws IOException {
		setServerConnection(port);
		client = new Client();
		if(encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			encryptType = encryptScheme;
		}
		
	}
	public Server(int port, String encryptScheme, byte [] key, AsymmetricKeyParameter clientPub) throws IOException {
		setServerConnection(port);
		client = new Client();
		if(encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			encryptType = encryptScheme;
		}
		if(key.length == DEFAULT_KEY_LENGTH) {
			this.setKey(key);
		}
		this.setClientPub(clientPub);
		
		
		
	}
	public Server(int port, String encryptScheme, byte [] key,AsymmetricKeyParameter clientPub, AsymmetricCipherKeyPair keyPair) throws IOException {
		setServerConnection(port);
		client = new Client();
		if(encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			encryptType = encryptScheme;
		}
		if(key.length == DEFAULT_KEY_LENGTH) {
			this.setKey(key);
		}
		this.setKeyPair(keyPair);
		this.setClientPub(clientPub);
		
	}
	//Starts the server and waits for connections
	public void start() throws IOException {
		client.setClientConnection( (SocketConnection) serverConnection.acceptAndOpen());
		os = client.getClientConnection().openDataOutputStream();
		
	}
	
	//Closes associated resources
	public void close() throws IOException {
		
		serverConnection.close();
		client.close();
		os.close();
		is.close();
        this.is = null;
		
		
		return;
	}
	
	public Message receiveAndProcess(int maxReceiveSize) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
		
		//Receive data over the network
		byte [] receivedData = receiveDataRaw(maxReceiveSize);
		if(receivedData == null || receivedData.length < 4) {
			throw new IllegalArgumentException("Invalid message received.");
			
		}
		//Parse data into message object
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
	
	
	//Receives data from client with a max receiving size
	public byte [] receiveDataRaw(int maxReceiveSize) throws IOException{
    	
    	if(is == null) {
			try {
				is = client.getClientConnection().openDataInputStream();
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
		if(received.length < 4) {
    		close();
    		throw new IllegalArgumentException("Invalid Message Size Received");
    	}
        
        if(bytesRead > maxReceiveSize){
        	System.out.println("Data read exceeded input buffer, some data may have been lost");
        }
        else if(bytesRead == -1 || bytesRead == 0) {
        	return null;
        }
        System.out.println("Bytes read: " + bytesRead);
       
        
    	return received;
    }
	
	//Encrypts and sends data based on encryption scheme
	
	//TODO: 
	 public boolean sendMessage(byte [] message, byte [] extraData) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException {
	    	
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
	    				
	    				Message newMessage = new Message("MSG", encryptType, encryptor.getCipherText(), extraData, encryptor.getMac(), nonce);
	    				
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
	 public boolean sendRaw(byte [] message){
		 
		 if(os != null){
			try{
				os.write(message);
				return true;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	    return false;
	 }
	 public boolean sendKey() throws IOException, InvalidKeyException {
		 if(this.getKeyPair() != null) {
			 byte [] pubkey = KeyGen.getPublicKey(this.getKeyPair().getPublic());
			 
			 
			 Message newMessage = new Message("KEY", pubkey);
    			
 			 try{
 				 os.write(newMessage.createMessage());
 				 return true;
				} catch (IOException e) {
					e.printStackTrace();
				}
			 
		 }
		 else {
			 throw new InvalidKeyException("No key pair initialized.");
		 }
		 return false;
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
		 
		 
		 this.setClientPub(KeyGen.createPublicParamFromKey(clientkey));
		 KeyGen keyGen = new KeyGen();
		 //No keypair provided, gen one
		 if(this.keyPair == null) {
			this.setKeyPair(keyGen.ECgenerateKeyPair());
		 }
		 
		 //Generate secret key
		 this.setKey(keyGen.ECgenerateSecret(this.keyPair.getPrivate(), this.getClientPub()));
		 
		 //Derive key
		 byte [] derivedKey = keyGen.deriveSymmetricKey(this.keyPair.getPublic(), this.getClientPub(), this.getKey());
		 
		 this.setKey(derivedKey);
		
	 }
	 
	 //Authenticate and decrypt message for AES encryption method
	 private Message processAES(Message msg) throws InvalidKeyException, ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		 Encryption decrypter = new Encryption();
		 
		 if(this.key != null) {
				String mac = new String(msg.getMac());
				//Validate MAC
				if(!mac.equals("null")) {
					if(Authentication.verifyHMAC( new MD5Digest(), msg.getMac(), msg.getMessage(),key)){	
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
	 public Message processGCM(Message msg) throws InvalidCipherTextException {
		 
		 Encryption decrypter = new Encryption();
		 
		 if(this.key != null) {
			
			 byte [] cipherAndTag = new byte [msg.macLength+msg.msgLength];
			 System.arraycopy(msg.getMessage(), 0, cipherAndTag, 0, msg.getMsgLength());
			 System.arraycopy(msg.getMac(), 0, cipherAndTag, msg.getMsgLength(), msg.getMacLength());			 
			 msg.setMessage(decrypter.gcmDecrypt(this.key, cipherAndTag, msg.getAdditionalData(), msg.getNonce()));

			 if(msg.getMessage() == null) {
				throw new InvalidCipherTextException("Invalid MAC, message authentication failed.");
			 }
		 }
			
		return msg;
	 }
	 

	 	 
	//**Getters & Setters**//
	public ServerSocketConnection getServerConnection() {
		return serverConnection;
	}

	public void setServerConnection(ServerSocketConnection serverConnection) {
		this.serverConnection = serverConnection;
	}
	
	public void setServerConnection(int port) throws IOException {
		if(port < 1 || port > 65535)
        {
        	throw new IllegalArgumentException("Port out of Range: Must be between 1 and 65535");
        }
		this.serverConnection = (ServerSocketConnection) Connector.open("socket://:" + port);
		
	}

	public Client getListener() {
		return client;
	}

	public byte[] getKey() {
		return key;
	}

	public void setKey(byte[] key) {
		
		if(key.length == DEFAULT_KEY_LENGTH) {
			this.key = key;
		}else {
			throw new IllegalArgumentException("Invalid Key size.");
		}
	}

	public AsymmetricCipherKeyPair getKeyPair() {
		return keyPair;
	}

	public void setKeyPair(AsymmetricCipherKeyPair keyPair) {
		this.keyPair = keyPair;
	}
	public String getEncryptType() {
		return encryptType;
	}
	public void setEncryptType(String encryptType) {
		this.encryptType = encryptType;
	}
	public AsymmetricKeyParameter getClientPub() {
		return clientPub;
	}
	public void setClientPub(AsymmetricKeyParameter clientPub) {
		this.clientPub = clientPub;
	}
	
	

}
