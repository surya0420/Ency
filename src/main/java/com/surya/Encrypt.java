//package com.surya;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.io.UnsupportedEncodingException;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidKeyException;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.util.Arrays;
//import java.util.Base64;
//
//public class Encrypt {
//
//    public static void main(String[] args) {
//        String key="asdfghjklqwertyuasdfghjklqwertyuwefwefwefwegfwefwefwef";
//        String agtbKey ="AGTBBASEAPP"+"+919040414412";
//        String toBeEncrypted ="/4?legalEntityName=2GI6A48Z69&entityName=ANGLO-GULF TRADE BANK (AGTB) LIMITED&documentType=4&operationType=onboarding&fileName=2GI6A48Z69_Proof_of_operating_address_202122516266620_1614237354293.pdf";
//String ency = AppzillonAESUtils.encryptString(agtbKey, toBeEncrypted);
//        System.out.println("ency====>"+ency);
//        String agbtEncy ="IYFj0R/cQtVtMk9uy+kJ0wifUtjLpIWKyxhqSzQs5cxw521YHVbJoJ8Pz1m/IZg/TuY1Vd4TeLbNcIs6XBifmEM4Dwsi+31gwvk3uLTj3KnuPAQ4HyTxyD1W04d35wbGOtw78/2m68q/vDlsq0Yp8ZMFHKWAtzWuEcmpGyAoiMuOrXfNLPCLOHhRNk5c/n+p4mJc+jTgZjHk5G0te/aV4uB+WtHD88/Q4JR6vV5Jsa9sQsDUtnlsaGQWy9r7DBgdGAdXfWLsZfMxODXUEDRMe92FhEnqLAAO5DgILjQDEs=";
////String agtbKey ="\u001C�\u0004f\u0012���\tQ�A����";
//        System.out.println("decrypted  "+AppzillonAESUtils.decryptString(agtbKey,ency));
//    }
//
//
//    public static String getAESdecryptedFromJS(SecretKeySpec key, IvParameterSpec iv, String cipherText) {
//        System.out.println("AESdecryptedFromJS CipherText :" + cipherText);
//        String decryptedText = "";
//        try {
//            byte[] cipherData = Base64.getDecoder().decode(cipherText);
//            Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
//           // Cipher aesCBC = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
//            byte[] decryptedData = aesCBC.doFinal(cipherData);
//            decryptedText = new String(decryptedData, "UTF-8");
//        } catch (Exception ex) {
//            System.out.println("Exception Occurred!!! ");
//            ex.printStackTrace();
//            decryptedText = "FAILURE";
//        }
//        return decryptedText;
//    }
//
//    public static String getAESencryptedForJS(SecretKeySpec key, IvParameterSpec iv, String plainText) {
//        System.out.println("AESencryptedForJS PlainText :" + plainText);
//        String cipherText = "";
//        try {
//           Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
//          //  Cipher aesCBC = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            aesCBC.init(Cipher.ENCRYPT_MODE, key, iv);
//            byte[] encryptedData = aesCBC.doFinal(plainText.getBytes());
//            cipherText = Base64.getEncoder().encodeToString(encryptedData);
//            System.out.println("encrypted Text -:" + cipherText);
//        } catch (Exception ex) {
//            System.out.println("Exception Occurred!!! "+ex);
//            ex.printStackTrace();
//            cipherText = "FAILURE";
//        }
//        return cipherText;
//    }
//    private static String getKey(String key) {
//        System.out.println("get Key value");
//        String result = null;
//        if (key.length() < 32) {
//            StringBuilder temp = new StringBuilder(key);
//            for (int i = key.length(); i < 16; i++) {
//                temp.append("$");
//            }
//            System.out.println("Key: " + temp.toString());
//            result = temp.toString();
//        } else if (key.length() > 32) {
//            String finalKey = key.substring(0, 16);
//            System.out.println("Key: " + finalKey);
//            result = finalKey;
//        } else {
//            System.out.println("Key: " + key);
//            result = key;
//        }
//        return result;
//    }
//
//    private static String toBase64Encode(byte[] data) {
//        return Base64.getEncoder().encodeToString(data);
//    }
//
//    private static byte[] getIV(String key) {
//        byte[] iv = new byte[16];
//        java.util.Arrays.fill(iv, (byte) 0);
//        StringBuilder or = new StringBuilder(key);
//        String nw = or.reverse().toString();
//        byte[] keyBytes = null;
//        try {
//            keyBytes = nw.getBytes("UTF-8");
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        byte[] rawIV = new byte[keyBytes.length];
//        for (int i = 0; i < keyBytes.length; i++) {
//            rawIV[i] = (byte) (keyBytes[i] >> 1);
//        }
//        for (int i = 0; i < iv.length; i++) {
//            iv[i] = rawIV[i];
//        }
//        return iv;
//    }
//
//
//    public static String decryptString(String pkey, String pencrypted) {
//       // System.out.println("{} Decrypting String ", ServerConstants.LOGGER_PREFIX_RESTFULL);
//        String originalString = "";
//        try {
//            byte[] key = (pkey).getBytes(StandardCharsets.UTF_8);
//
//            MessageDigest sha = MessageDigest.getInstance(SHA_1);
//            key = sha.digest(key);
//            key = Arrays.copyOf(key, 16); // use only first 128 bit
//          //  System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "Key for encrytion:" + new String(key));
//            SecretKeySpec secretKeySpec = new SecretKeySpec(key, AES);
//
//            Cipher cipher = Cipher.getInstance(AES);
//            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
//
//            byte[] original = cipher.doFinal(Base64.decodeBase64(pencrypted));
//            originalString = new String(original);
//           // LOG.trace("{} originalString : {}", ServerConstants.LOGGER_PREFIX_RESTFULL , originalString);
//
//        } catch (UnsupportedEncodingException e) {
//            //System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "UnsupportedEncodingException",e);
//        } catch (InvalidKeyException e) {
//            //System.out.println(ServerConstants.LOGGER_PREFIX_RESTFULL + "InvalidKeyException",e);
//        } catch (NoSuchAlgorithmException e) {
//            //LOG.error(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchAlgorithmException",e);
//        } catch (BadPaddingException e) {
//           // LOG.error(ServerConstants.LOGGER_PREFIX_RESTFULL + "BadPaddingException",e);
//        } catch (IllegalBlockSizeException e) {
//           // LOG.error(ServerConstants.LOGGER_PREFIX_RESTFULL + "IllegalBlockSizeException",e);
//        } catch (NoSuchPaddingException e) {
//            //LOG.error(ServerConstants.LOGGER_PREFIX_RESTFULL + "NoSuchPaddingException",e);
//        }
//        return originalString;
//
//    }
//
//}
