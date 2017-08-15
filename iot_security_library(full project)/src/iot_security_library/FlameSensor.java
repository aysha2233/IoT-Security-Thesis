package iot_security_library;

import java.io.IOException;

import jdk.dio.ClosedDeviceException;
import jdk.dio.DeviceManager;
import jdk.dio.DeviceNotFoundException;
import jdk.dio.InvalidDeviceConfigException;
import jdk.dio.UnavailableDeviceException;
import jdk.dio.UnsupportedDeviceTypeException;
import jdk.dio.gpio.GPIOPin;
import jdk.dio.gpio.GPIOPinConfig;
import jdk.dio.gpio.PinEvent;
import jdk.dio.gpio.PinListener;

public class FlameSensor {
	
	private GPIOPin pin = null;  
	
	@SuppressWarnings("deprecation")
	public FlameSensor(int pinGPIO) throws InvalidDeviceConfigException, UnsupportedDeviceTypeException, DeviceNotFoundException, UnavailableDeviceException, IOException { 
		
		   pin = (GPIOPin) DeviceManager.open(new GPIOPinConfig( 0, pinGPIO,GPIOPinConfig.DIR_INPUT_ONLY,GPIOPinConfig.MODE_INPUT_PULL_UP, GPIOPinConfig.TRIGGER_RISING_EDGE, false));
		
		}
	
	public void setListener(PinListener flameListener) throws ClosedDeviceException, IOException {
		
		     if (pin!=null)
		          pin.setInputListener(flameListener);
		
		}
	public void close() throws ClosedDeviceException, IOException {
		
		       if (pin!=null){
		            pin.setInputListener(null);
		            pin.close();
		       }
		
		}
	public boolean getData() throws UnavailableDeviceException, ClosedDeviceException, IOException{
		return pin.getValue();
	}
	
}

class FlameDetector implements PinListener {
		private static int waitnext = 1;
        public void valueChanged(PinEvent event) {
            if (event.getValue() && --waitnext == 0) {
                System.out.println("WARNING Flame detected!!!");
                waitnext = 10;
            }
         }
    }

