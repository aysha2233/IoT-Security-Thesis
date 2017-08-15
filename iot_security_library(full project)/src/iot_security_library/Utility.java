package iot_security_library;

public class Utility {
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	
	public static void printFormatedByteArray ( byte [] array){
        for(byte c : array) {
            System.out.format("%x ", c);
        }
        System.out.println();
    }
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
	
	
	public static byte[] convertShortToByte(short val) {
		
		byte [] ret = new byte[2];
		
		ret[0] = (byte)(val & 0xff);
		ret[1] = (byte)((val >> 8) & 0xff);
		
		return ret;
	}
	public static short convertByteToShort(byte [] val) {
		int num = val[1] & 0xFF; 
		num = (num << 8) | (val[0] & 0xFF);
		
		return (short) num;
	}

}
