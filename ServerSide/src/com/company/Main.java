package com.company;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {

    static String publicK="",privateK ="";
    static CA ca;
    public static void readPublicAndPrivate(){
        try {
            File f = new File("public");
            FileReader fr = new FileReader(f);
            int i;
            publicK = "";
            while ((i = fr.read()) != -1)
                publicK += (char) i;
            f = new File("private");
            fr = new FileReader(f);
            privateK = "";
            while ((i = fr.read()) != -1)
                privateK += (char) i;
            PublicKey pubk = ASymmetric.string2PublicKey(publicK);
            PrivateKey prik = ASymmetric.string2PrivateKey(privateK);
            ASymmetric.setPublicKey(pubk);
            ASymmetric.setPrivateKey(prik);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    public static String CSR(String Domain,String PK){
        String s = "Domain:"+Domain+"\n";
        s+="Public Key:"+PK;
        return s;
    }

    public static String SignedDigitalCertificate(){
        return ca.Sign(CSR("PasswordManager.com",publicK));
    }


    public static void main(String[] args) throws IOException
    {
        ca = new CA();
        readPublicAndPrivate();
        try (ServerSocket listener = new ServerSocket(8080))
        {
            System.out.println("server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(30);
            while (true) {
                pool.execute(new Server(listener.accept(),SignedDigitalCertificate(),ca));
            }
        }
    }
}
