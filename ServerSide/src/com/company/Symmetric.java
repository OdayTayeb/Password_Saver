package com.company;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class Symmetric {
    private String key;
    private String iv;
    private boolean mustEnc = false;
    private Cipher cipher;

    public String enc(String dataToEncrypt){
        if (!mustEnc) return dataToEncrypt;
        try {
            IvParameterSpec initV = new IvParameterSpec(iv.getBytes());
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, initV);
            byte[] encrypted = cipher.doFinal(dataToEncrypt.getBytes());
            String s = Base64.getEncoder().encodeToString(encrypted);
            return s;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }

    public void initKey(byte[] keyByte){
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyByte, "AES");
        String encodedKey = Base64.getEncoder().encodeToString(secretKeySpec.getEncoded());
        System.out.println(encodedKey);
    }

    public String dec(String decryptedData){
        if (!mustEnc) return decryptedData;
        try {
            byte[] encrypted = Base64.getDecoder().decode(decryptedData);
            IvParameterSpec initV = new IvParameterSpec(iv.getBytes());
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, initV);
            byte[] decrypted = cipher.doFinal(encrypted);
            String s = new String(decrypted, StandardCharsets.UTF_8);
            return s;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }

    public void encFile(File myFile, File encrypted){
        if (!mustEnc) return ;
        try {
            IvParameterSpec initV = new IvParameterSpec(iv.getBytes());
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, initV);
            FileInputStream inputStream = new FileInputStream(myFile);
            byte[] inputBytes = new byte[(int) myFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);
            FileOutputStream outputStream = new FileOutputStream(encrypted);
            outputStream.write(outputBytes);
            inputStream.close();
            outputStream.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void decFile(File encrypted,File myFile){
        if (!mustEnc) return ;
        try {
            IvParameterSpec initV = new IvParameterSpec(iv.getBytes());
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, initV);
            FileInputStream inputStream = new FileInputStream(encrypted);
            byte[] inputBytes = new byte[(int) encrypted.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);
            FileOutputStream outputStream = new FileOutputStream(myFile);
            outputStream.write(outputBytes);
            inputStream.close();
            outputStream.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public String MAC(String data){
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
            mac.init(secretKeySpec);

            return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
            //return new String( mac.doFinal(data.getBytes()) );
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }

    public void START(String key){
        this.key = key;
        mustEnc = true;
    }

    public void END(){
        this.key="";
        mustEnc =false;
    }

    public String initIV(){

        // 32 - 126
        final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(16);
        for(int i = 0; i < 16; i++)
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        return iv = sb.toString();
        /*
        // 32 - 126
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(16);
        for(int i = 0; i < 16; i++)
            sb.append((char)(32+(rnd.nextInt(95))));
        return sb.toString();
        */
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public boolean getmustEnc(){
        return mustEnc;
    }

}
