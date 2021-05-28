package com.surya;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class AppzillonAESUtils {

    private static final String SHA_1 = "SHA-1";
	private static final String UTF_8 = "UTF-8";
    private static final String AES = "AES";

//	private static final Logger LOG = LoggerFactory.getLoggerFactory().getRestServicesLogger(
//            ServerConstants.LOGGER_RESTFULL_SERVICES, AppzillonAESUtils.class.getName());

    
    public static String encryptString(String pkey, String poriginalstring) {
		//System.out.println("{} encryting String ", ServerConstants.LOGGER_PREFIX_RESTFULL);
        String encyptedstring = "";
        try {
            byte[] key = (pkey).getBytes(UTF_8);

            MessageDigest sha = MessageDigest.getInstance(SHA_1);
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit
           // LOG.trace("{} Key for encrytion : {}", ServerConstants.LOGGER_PREFIX_RESTFULL, new String(key));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);

            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] encrypted = cipher.doFinal((poriginalstring).getBytes());

            encyptedstring = Base64.encodeBase64String(encrypted);
            //LOG.trace("{} length encrypted string : {}", ServerConstants.LOGGER_PREFIX_RESTFULL, encyptedstring.length());

        } catch (UnsupportedEncodingException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "UnsupportedEncodingException", e);
        } catch (InvalidKeyException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "InvalidKeyException", e);
        } catch (NoSuchAlgorithmException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchAlgorithmException", e);
        } catch (BadPaddingException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "BadPaddingException", e);
        } catch (IllegalBlockSizeException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "IllegalBlockSizeException", e);
        } catch (NoSuchPaddingException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchPaddingException", e);
        }
        return encyptedstring;
    }

    public static String decryptString(String pkey, String pencrypted) {
		//System.out.println("{} Decrypting String ", ServerConstants.LOGGER_PREFIX_RESTFULL);
        String originalString = "";
        try {
            byte[] key = (pkey).getBytes(UTF_8);

            MessageDigest sha = MessageDigest.getInstance(SHA_1);
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Key for encrytion:" + new String(key));
			//key =Base64.decodeBase64(�f���	Q�A����)
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);

            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            byte[] original = cipher.doFinal(Base64.decodeBase64(pencrypted));
            originalString = new String(original);
           //LOG.trace("{} originalString : {}", ServerConstants.LOGGER_PREFIX_RESTFULL , originalString);

        } catch (UnsupportedEncodingException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "UnsupportedEncodingException");
        } catch (InvalidKeyException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "InvalidKeyException");
        } catch (NoSuchAlgorithmException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchAlgorithmException");
        } catch (BadPaddingException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "BadPaddingException");
        } catch (IllegalBlockSizeException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "IllegalBlockSizeException");
        } catch (NoSuchPaddingException e) {
			System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchPaddingException");
        }
        return originalString;

    }

    
     public static String getExpirableKey(boolean eXPInMin,boolean eXPInHr,boolean eXPInDay) {

        Timestamp t = new Timestamp(new Date().getTime());

        Calendar lCalendar = Calendar.getInstance();
        lCalendar.setTimeInMillis(t.getTime());
        if( eXPInMin){
        lCalendar.set(Calendar.SECOND, 0);
        lCalendar.set(Calendar.MILLISECOND, 0);
        }else if ( eXPInHr){
        	 lCalendar.set(Calendar.MINUTE, 0);
             lCalendar.set(Calendar.SECOND, 0);
             lCalendar.set(Calendar.MILLISECOND, 0);
        	
        }else if ( eXPInDay){
        	 lCalendar.set(Calendar.HOUR_OF_DAY, 0);
             lCalendar.set(Calendar.MINUTE, 0);
             lCalendar.set(Calendar.SECOND, 0);
             lCalendar.set(Calendar.MILLISECOND, 0);
        }
        Timestamp date = new Timestamp(lCalendar.getTimeInMillis());
        return  date.toString();
    }
     
  // key generator method
  public static byte[] hmacSha1(String salt, String key, int safeBit) {
	  SecretKeyFactory factory = null;
	  Key keyByte = null;
	  KeySpec keyspec = null;
	  try {
		  if (safeBit == 0) {
			  factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			  keyspec = new PBEKeySpec(key.toCharArray(),
					  salt.getBytes("UTF-8"), 2, 128);
		  } else {
			  factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			  keyspec = new PBEKeySpec(key.toCharArray(), salt.getBytes("UTF-8"), 2, 256);
		  }

		  keyByte = factory.generateSecret(keyspec);
	  } catch (NoSuchAlgorithmException e) {
		  //System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception", e);
	  } catch (InvalidKeySpecException e) {
		  //System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception", e);
	  } catch (UnsupportedEncodingException e) {
		  //System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception", e);
	  }
	  return keyByte.getEncoded();
  }

 	// encryption method
 	public  static String encryptString(String cypher, String key, String clearText, String salt, byte[] iv, String pOS, int safeBit) {
 		SecretKeySpec skeySpec = null;
 		if(ServerConstants.OS_BLACKBERRY_10.equalsIgnoreCase(pOS)){
 			skeySpec = new SecretKeySpec(salt.getBytes(), "AES");
 		}else {
 			skeySpec = new SecretKeySpec(hmacSha1(salt, key, safeBit), "AES");
 		}

 		try {
 			Cipher cipher = Cipher.getInstance(cypher);
 			//iv = ivText.getBytes();
 			// random.nextBytes(iv);
 			IvParameterSpec ivParams = new IvParameterSpec(iv);
 			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParams);
 			byte[] encryptedData = cipher.doFinal(clearText.getBytes("UTF-8"));
 			if (encryptedData == null)
 				return null;
 			return Base64.encodeBase64String(encryptedData);
 		} catch (Exception e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception",e);
 		}
 		return null;
 		/**/
 	}

 	// decryption method
 	public  static String decryptString(String cypher, String key,
										String textToDecrypt, String salt, byte[] iv, String pOS, int safeBit) {
		System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Cipher -:" + cypher + ", key:"+ key + ", texToDecrypt :" + textToDecrypt + ", salt :" + salt + ", iv:" + iv + ", OS -:" + pOS);
 		SecretKeySpec skeySpec = null;
 		if(ServerConstants.OS_BLACKBERRY_10.equalsIgnoreCase(pOS)){
 			skeySpec = new SecretKeySpec(salt.getBytes(), "AES");
 		}else {
 			skeySpec = new SecretKeySpec(hmacSha1(salt, key, safeBit), "AES");
 		}
 		
 		try {
 			Cipher cipher = Cipher.getInstance(cypher);
 			IvParameterSpec ivParams = new IvParameterSpec(iv);
 			cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParams);
 			byte[] plaintext = cipher.doFinal(Base64.decodeBase64(textToDecrypt));
 			String plainrStr = new String(plaintext, "UTF-8");
 			return new String(plainrStr);
 		} catch (Exception e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception",e);
 		}
 		return null;
 	}
 	/**
	 * prepares the IV from key
	 * @param key
	 * @return
	 */
	public static byte[] getIV(String key) {
		byte[]iv = new byte[16];
		Arrays.fill(iv, (byte)0);
		StringBuffer or = new StringBuffer(key);
		String nw = or.reverse().toString();
		byte[]keyBytes = null;
		try {
			keyBytes = nw.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			//System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Exception", e);
		}
		byte[]rawIV = new byte[keyBytes.length];
		for (int i = 0; i < keyBytes.length; i++) {
			rawIV[i] = (byte)(keyBytes[i] >> 1);
		}
		for (int i = 0; i < iv.length; i++) {
			iv[i] = rawIV[i];
		}
		return iv;
	}
	
	/**
	 * Prepares the salt based on key
	 *
	 * @param key
	 * @return
	 */
	public static String getSalt(String key) {
		// TODO Auto-generated method stub
		String originalString = key;

		char[]c = originalString.toCharArray();

		// Replace with a "swap" function, if desired:
		char temp = c[0];
		c[0] = c[1];
		c[1] = temp;

		temp = c[c.length - 1];
		c[c.length - 1] = c[c.length - 2];
		c[c.length - 2] = temp;
		String swappedString = new String(c);
		return swappedString;
	}
	
//	public static String decryptContainerString(String pCipherString, String pKey, Message pMessage){
//		String decryptedString = null;
//		String lKey = getPaddedKey(pKey);
//		System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL+ " decryptContainerString key for encryption after checking the length -:"
//				+ lKey);
//		byte[] iv = AppzillonAESUtils.getIV(lKey);
//		String finalSalt = AppzillonAESUtils.getSalt(lKey);
//		decryptedString = AppzillonAESUtils.decryptString(ServerConstants.PBS_PADDING, lKey, pCipherString,
//						finalSalt, iv, pMessage.getHeader().getOs(), pMessage.getHeader().getSafeBit());
//		System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL
//				+ " decryptContainerString Decrypted AppzillonBody -:"+ decryptedString);
//		return decryptedString;
//	}

	private static String getPaddedKey(String pKey) {
		String lKey = pKey;
		String paddingMask = "$$$$$$$$$$$$$$$$";
		if (lKey.length() <= 16) {
			lKey += paddingMask.substring(0, 16 - lKey.length());
		}
		if (lKey.length() > 16) {
			lKey = lKey.substring(0, 16);
		}
		return lKey;
	}
//	public static String encryptStringtoContainer(String pPlainText, String pKey, Message pMessage){
//		String encryptedString = null;
//		String lKey = getPaddedKey(pKey);
//		System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL+ " encryptStringtoContainer key for decryption after checking the length -:"
//				+ lKey);
//
//		byte[] iv = AppzillonAESUtils.getIV(lKey);
//		String finalSalt = AppzillonAESUtils.getSalt(lKey);
//
//		encryptedString = AppzillonAESUtils.encryptString(ServerConstants.PBS_PADDING,
//				lKey, pPlainText, finalSalt, iv, pMessage.getHeader().getOs(), pMessage.getHeader().getSafeBit());
//		System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL
//				+ " encryptStringtoContainer Encrypted Body -:" + encryptedString);
//		return encryptedString;
//
//	}
	
/*	public static void main(String args[]){
		String encryptedText = "oPOrhcnVMjogsPlSjF5PKXipxe6IP/4uuGjQoWKx050=";
		String key = "12345com.iexceed.qateam" ;
		String paddingMask = "$$$$$$$$$$$$$$$$";
		String planReq = "{\"ChannelId\":\"BALANCEINQ_REQ\"}";
		System.out.println("key.length() -:" + key.length());
		if (key.length() <= 16) {
			key += paddingMask.substring(0, 16 - key.length());
		}
		if(key.length()>16){
			key = key.substring(0,16);
		}
		System.out.println("key -:" +  key);
		byte[]iv = AppzillonAESUtils.getIV(key);
		String finalSalt = AppzillonAESUtils.getSalt(key);
		String PBS_PADDING = "AES/CBC/PKCS5padding";
		String encryptS = AppzillonAESUtils.encryptString(PBS_PADDING, key, planReq, finalSalt, iv);
		System.out.println("encryptS -:" + encryptS);
		String decryptedString = AppzillonAESUtils.decryptString(PBS_PADDING, key, encryptS, finalSalt, iv);
		System.out.println("decryptedString -:" + decryptedString);
		
	}*/
}
