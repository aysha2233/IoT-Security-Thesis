package iot_security_library;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Message {
	
	public byte [] msgType = "MSG".getBytes(); //Type of message; key exchange (KEY) or message (MSG)
	public byte [] encryptScheme = "NUL".getBytes();//Encrypt Scheme being used
	public short msgLength = 4;//data length
	public short macLength = 4;//length of mac
	public short additionalDataLength = 4;
	public short nonceLength = 4; // lenght of nonce
	public byte [] message = "null".getBytes();//message in bytes
	public byte [] mac = "null".getBytes(); //mac in bytes
	public byte [] additionalData = "null".getBytes();//additional, non encrypted data
	public byte [] nonce = "null".getBytes();//used in GCM 
	//public int clientNum = 0;//Possibly add additional field to support multiple connections in Server class
	
	
	public byte [] finalMessage = "null".getBytes();//fully concatenated byte array
	
	
	public Message() {
		//Empty constructor
	}
	//No Encrypt Scheme
	public Message(String msgType, String encryptScheme, byte [] message) {
		
		
		if(msgType.equals("MSG") || msgType.equals("KEY")) {
			if(encryptScheme.equals("NUL") || encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			
				//Assign vars
				this.msgType = msgType.getBytes();
				this.encryptScheme = encryptScheme.getBytes();
				
				if(additionalData == null) {
					this.additionalData = "null".getBytes();
				}
				else {
					this.additionalData = additionalData;
				}
				if(message == null) {
					this.message = "null".getBytes();
				}
				else {
					this.message = message;
				}
				
				//Compute lengths
				this.msgLength = (short) this.message.length;
				this.additionalDataLength = (short) this.additionalData.length;
				
				
			}
			else {
				throw new IllegalArgumentException("Invalid encryption scheme.");
			}
		}
		else {
			throw new IllegalArgumentException("Invalid message type.");
			
		}
	}
	
	//AES
	public Message(String msgType, String encryptScheme, byte [] message, byte [] additionalData, byte [] mac) {
			
		if(msgType.equals("MSG") || msgType.equals("KEY")) {
			if(encryptScheme.equals("NUL") || encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			
				//Assign vars
				this.msgType = msgType.getBytes();
				this.encryptScheme = encryptScheme.getBytes();
				
				if(additionalData == null) {
					this.additionalData = "null".getBytes();
				}
				else {
					this.additionalData = additionalData;
				}
				if(message == null) {
					this.message = "null".getBytes();
				}
				else {
					this.message = message;
				}
				
				if(mac == null) {
					this.mac = "null".getBytes();
				}
				else {
					this.mac = mac;
				}
				
				//Compute lengths
				this.msgLength = (short) this.message.length;
				this.additionalDataLength = (short) this.additionalData.length;
				this.macLength = (short) this.mac.length;
				
			}
			else {
				throw new IllegalArgumentException("Invalid encryption scheme.");
			}
		}
		else {
			throw new IllegalArgumentException("Invalid message type.");
			
		}
		
	}
	//GCM
	public Message(String msgType, String encryptScheme, byte [] message, byte [] additionalData, byte [] mac, byte [] nonce) {
		
		 

		if(msgType.equals("MSG") || msgType.equals("KEY")) {
			if(encryptScheme.equals("NUL") || encryptScheme.equals("GCM") || encryptScheme.equals("AES")) {
			
			//Assign vars
				this.msgType = msgType.getBytes();
				this.encryptScheme = encryptScheme.getBytes();
				
				if(additionalData == null) {
					this.additionalData = "null".getBytes();
				}
				else {
					this.additionalData = additionalData;
				}
				if(message == null) {
					this.message = "null".getBytes();
				}
				else {
					this.message = message;
				}
				
				if(mac == null) {
					this.mac = "null".getBytes();
					
				}
				else {
					this.mac = mac;
				}
				if(nonce == null) {
					this.nonce = "null".getBytes();
				}
				else {
					this.nonce = nonce;
				}
				
				//Compute lengths
				this.msgLength = (short) this.message.length;
				this.additionalDataLength = (short) this.additionalData.length;
				this.macLength = (short) this.mac.length;
				this.nonceLength = (short) this.nonce.length;
			}
			else {
				throw new IllegalArgumentException("Invalid encryption scheme.");
			}
		}
		else {
			throw new IllegalArgumentException("Invalid message type.");
			
		}
		
		
	}
	
	public Message(String msgType, byte[] message) {
		this.setMsgType(msgType.getBytes());
		this.setMessage(message);
	}
	
    //Creates a byte array to sending
	public byte [] createMessage() throws IOException {
	 
				
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(this.msgType);
		outputStream.write(this.encryptScheme);
		outputStream.write(Utility.convertShortToByte(this.msgLength));
		outputStream.write(Utility.convertShortToByte(this.macLength));
		outputStream.write(Utility.convertShortToByte(this.additionalDataLength));
		outputStream.write(Utility.convertShortToByte(this.nonceLength));
		outputStream.write(this.message);
		outputStream.write(this.mac);
		outputStream.write(this.additionalData);
		outputStream.write(this.nonce);
				
		
		this.finalMessage = outputStream.toByteArray( );
		
		return finalMessage;
	}
	
	//Getters and Setters
	public byte[] getMsgType() {
		return msgType;
	}
	public void setMsgType(byte[] msgType) {
		this.msgType = msgType;
	}
	public byte[] getMac() {
		return mac;
	}
	public void setMac(byte[] mac) {
		this.mac = mac;
		this.setMacLength((short)mac.length);
	}
	public byte[] getEncryptScheme() {
		return encryptScheme;
	}
	public void setEncrypScheme(byte[] encrypScheme) {
		this.encryptScheme = encrypScheme;
	}
	public short getMsgLength() {
		return msgLength;
	}
	public void setMsgLength(short msgLength) {
		this.msgLength = msgLength;
	}
	public short getMacLength() {
		return macLength;
	}
	public void setMacLength(short macLength) {
		this.macLength = macLength;
	}
	public byte[] getMessage() {
		return message;
	}
	public void setMessage(byte[] message) {
		this.message = message;
		this.setMsgLength((short)message.length);
	}
	public byte[] getAdditionalData() {
		return additionalData;
	}
	public void setAdditionalData(byte[] additionalData) {
		this.additionalData = additionalData;
		this.setAdditionalDataLength((short) additionalData.length);
	}
	public byte[] getNonce() {
		// TODO Auto-generated method stub
		return nonce;
	}
	public short getAdditionalDataLength() {
		// TODO Auto-generated method stub
		return additionalDataLength;
	}
	public void setAdditionalDataLength(short val) {	
		this.additionalDataLength = val;
	}
	public void setNonceLength(short val) {
		// TODO Auto-generated method stub
		this.nonceLength = val;
		
	}
	public void setNonce(byte[] var) {
		// TODO Auto-generated method stub
		this.nonce = var;
		this.setNonceLength((short) var.length);
	}
	public short getNonceLength() {
		// TODO Auto-generated method stub
		return this.nonceLength;
	}
	

}
