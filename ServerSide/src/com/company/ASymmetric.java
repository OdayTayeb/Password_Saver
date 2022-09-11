package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ASymmetric {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static int keySize = 1024;


    public static void setPrivateKey(PrivateKey p){
        privateKey = p;
    }
    public static void setPublicKey(PublicKey p){
        publicKey=p;
    }

    private static void generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public static void init() {
        try {
            generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public static synchronized String getPublicKeyAsString() {
        byte[] bytes = ASymmetric.publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static synchronized String getPrivateKeyAsString() {
        byte[] bytes = ASymmetric.privateKey.getEncoded();
        return byte2Base64(bytes);
    }


    public static synchronized PublicKey string2PublicKey(String pubStr) {
        try {
            byte[] keyBytes = base642Byte(pubStr);
            assert keyBytes != null;
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ASymmetric.publicKey;
    }

    public static synchronized PrivateKey string2PrivateKey(String priStr) {
        try {
            byte[] keyBytes = base642Byte(priStr);
            assert keyBytes != null;
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ASymmetric.privateKey;
    }


    public static PublicKey getPublicKey(){
        return publicKey;
    }




    public static synchronized String byte2Base64(byte[] bytes) {
        return Base64.getMimeEncoder().encodeToString(bytes);
    }

    public static synchronized byte[] base642Byte(String base64Key) {
        try {
            return Base64.getMimeDecoder().decode(base64Key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptMessage(String encryptedText, PrivateKey p) {
        if (p == null) p = ASymmetric.privateKey;
        try {


        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, p);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));}
        catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }


    public static String encryptMessage(String plainText, PublicKey p) throws Exception  {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, p);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static boolean verifySignature(String data,PublicKey p,String ClientSignature){
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(p);
            signature.update(data.getBytes("UTF-8"));
            return signature.verify(Base64.getDecoder().decode(ClientSignature));
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    public static String sign(String data){
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(privateKey, new SecureRandom());
            signature.update(data.getBytes("UTF-8"));
            byte[] signed= signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }
}
