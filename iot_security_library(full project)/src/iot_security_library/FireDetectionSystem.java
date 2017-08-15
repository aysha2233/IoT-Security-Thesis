package iot_security_library;

import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.InvalidCipherTextException;

import jdk.dio.DeviceNotFoundException;
import jdk.dio.InvalidDeviceConfigException;
import jdk.dio.UnavailableDeviceException;
import jdk.dio.UnsupportedDeviceTypeException;

public class FireDetectionSystem {
	private static final int FLAME_DETECTOR_PIN = 0;
    private static final int TEMPERATURE_SENSOR_CHANNEL = 0;
    private boolean tradedKey = false;
    
	public void runDetection( String encryptScheme) throws InvalidDeviceConfigException, UnsupportedDeviceTypeException, DeviceNotFoundException, UnavailableDeviceException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
		FlameSensor flame = null;
		TemperatureSensor temp = null;
		boolean noFlameDetected = true;
		int iterations = 100;
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
	      temp = new TemperatureSensor(TEMPERATURE_SENSOR_CHANNEL);
	      
	      //Do loop
	      for(int i = 0; i < iterations; i++){
	        	
	        	System.out.println("No flames detected....");
	        	Client connection = null;
	        	try {
	  				//System.out.println("Flame data value: " + flame.getData());
	        		noFlameDetected = flame.getData();
	        		
	        		
	        		if(!noFlameDetected) {
	        			if(connection == null) {
	        				connection = new Client("10.0.0.167",4040, encryptScheme);
	        				connection.start();
	        			}
	        			
	        			
	        			if(tradedKey == false) {
	        				System.out.println("Sending Key...");
	        				KeyGen keygen = new KeyGen();
	        				tradedKey = true;
	        				
	        				
	        				connection.setKeyPair(keygen.ECgenerateKeyPair());
	        				long startTime = System.nanoTime();
	        				connection.sendKey();
	        				long endTime = System.nanoTime();
	        				connection.receiveAndProcess(1024);
	        				
	        				float totalTime = (float)(endTime-startTime)/1000000;
	        				System.out.println("Key exchange time:" + totalTime);
	        			}
	        			String data = "Flame Detected! Temperature is: ";
	        			System.out.println("Sending data...");
	        			String tempVal = String.valueOf(temp.convertTemp((float)temp.getTemp()));
	        			String finalData = data +" " + tempVal;
	        			
	        			long startTime = System.nanoTime();
	        			connection.sendMessage(finalData.getBytes(), "No Extra Data".getBytes());
        				long endTime = System.nanoTime();
	        			float totalTime = (float)(endTime-startTime)/1000000;
        				System.out.println("Message send time:" + totalTime);
        				
	        			connection.receiveAndProcess(1024);
	        			connection.close();
	        			return;
	        			
	        		}
	        		
	        		
	        		
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
	public void serverAwaitDetection(int port, String encryptScheme) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidCipherTextException, DigestException {
		Server server = new Server(port, encryptScheme);
		server.start();
		Message messageReceived = null;
		
		while(true) {
			
			if(server == null) {
				server = new Server(port, encryptScheme);
				server.start();
			}
			messageReceived = server.receiveAndProcess(1024);
			
			
			if(this.tradedKey == false) {
				
				System.out.println("Keys exchanged.");
				this.tradedKey = true;
				long startTime = System.nanoTime();
				server.sendKey();
				long endTime = System.nanoTime();
				float totalTime = (float)(endTime-startTime)/1000000;
				System.out.println("Key exchange time:" + totalTime);

			}
			else {
				String data = new String(messageReceived.getMessage());
				System.out.println("Message Received: "+ data);
				Date date = new Date();
				String message = "Message received at: " + date.toString();
				long startTime = System.nanoTime();
				server.sendMessage(message.getBytes(), "User alerted".getBytes());
				long endTime = System.nanoTime();
				float totalTime = (float)(endTime-startTime)/1000000;
				System.out.println("Message time:" + totalTime);
				server.close();
				server = null;
				break;
			}
			
		}
		
		
		
	}
}
