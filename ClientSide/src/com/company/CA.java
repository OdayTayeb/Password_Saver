package com.company;

import java.io.File;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

public class CA {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CA(){
        try {
            File f = new File("CA/public.txt");
            FileReader fr = new FileReader(f);
            int i;
            String publicK = "";
            while ((i = fr.read()) != -1)
                publicK += (char) i;
            f = new File("CA/private.txt");
            fr = new FileReader(f);
            String privateK = "";
            while ((i = fr.read()) != -1)
                privateK += (char) i;
            publicKey = ASymmetric.string2PublicKey(publicK);
            privateKey = ASymmetric.string2PrivateKey(privateK);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    boolean check(){
        return true;
    }

    public String Sign(String data){
        if (check()){
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

        }
        return "";
    }

    public boolean verify(String data,String signedCSR){
        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(publicKey);
            signature.update(data.getBytes("UTF-8"));
            return signature.verify(Base64.getDecoder().decode(signedCSR));
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
}
