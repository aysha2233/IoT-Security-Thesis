package iot_security_library;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Enumeration;

import javax.microedition.io.Connector;
import javax.microedition.io.file.FileConnection;
import javax.microedition.io.file.FileSystemRegistry;

import org.bouncycastle.java.math.*;

import jdk.dio.DeviceManager;
import jdk.dio.DeviceNotFoundException;
import jdk.dio.InvalidDeviceConfigException;
import jdk.dio.RoundCompletionEvent;
import jdk.dio.UnavailableDeviceException;
import jdk.dio.UnsupportedDeviceTypeException;
import jdk.dio.adc.ADCChannel;
import jdk.dio.adc.ADCChannelConfig;
import jdk.dio.adc.AcquisitionRoundListener;



public class TemperatureSensor {
	private ADCChannel channel = null;
	public int B = 4275;               // B value of the thermistor
	public int R0 = 100000;            // R0 = 100k
	
	@SuppressWarnings("deprecation")
	public TemperatureSensor (int channelID) throws InvalidDeviceConfigException, UnsupportedDeviceTypeException, DeviceNotFoundException, UnavailableDeviceException, IOException{
		

	}
	
	public int getTemp() throws IOException {
		
		
		byte [] bytes = null;
		try {
	    FileConnection fc = (FileConnection)Connector.open("file:///root1/tempValsOutput", Connector.READ);

        if(!fc.exists()) {
            System.out.println("File doesn't exist!");
        }
        else {
            //int size = (int)fc.fileSize();
        	int size = 4;
            InputStream is = fc.openInputStream();
            bytes = new byte[size];
            
            is.read(bytes, 0, size);
            Utility.printFormatedByteArray(bytes);
           
            int temperature = byteArrayToInt(bytes);
            return temperature;
            
        }

		    } catch (IOException ioe) {
		        ioe.printStackTrace();
		    } catch (IllegalArgumentException iae) {
		    	iae.printStackTrace();
		    }
		    		return 0;
	}	
	public float convertTemp(float num) {
		
		float R = (float) (1023.0/num-1.0);
	    R = R0*R;
	     
	    float temperature = (float) (1.0/((log(R/R0)/log(10))/B+1/298.1)-273.15); // convert to temperature via datasheet
	    
	    
	    return (float) Math.ceil(temperature);

	}
	
	
	private static double pow(double base, int exp){
	    if(exp == 0) return 1;
	    double res = base;
	    for(;exp > 1; --exp)
	        res *= base;
	    return res;
	}

	public static double log(double x) {
	    long l = Double.doubleToLongBits(x);
	    long exp = ((0x7ff0000000000000L & l) >> 52) - 1023;
	    double man = (0x000fffffffffffffL & l) / (double)0x10000000000000L + 1.0;
	    double lnm = 0.0;
	    double a = (man - 1) / (man + 1);
	   
	    for( int n = 1; n < 7; n += 2) {
	        lnm += pow(a, n) / n;
	    }
	    return 2 * lnm + exp * 0.69314718055994530941723212145818;
	}
	
	
	public static int byteArrayToInt(byte[] b) 
	{
		    final ByteBuffer bb = ByteBuffer.wrap(b);
		    bb.order(ByteOrder.LITTLE_ENDIAN);
		    return bb.getInt();
	}
	
}	
	

