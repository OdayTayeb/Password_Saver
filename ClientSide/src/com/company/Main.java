package com.company;

import java.awt.image.BufferedImage;
import java.io.*;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    private static Symmetric symmetric = new Symmetric();
    private static DataOutputStream dataOutputStream;
    private static DataInputStream dataInputStream;
    private static PrintWriter out;
    private static Scanner in;
    private static Scanner scanner;
    private static boolean isLoggedIn = false;
    public static void main(String[] args) {
        try (Socket socket = new Socket("127.0.0.1", 8080)) {
            CA ca = new CA();
            scanner = new Scanner(System.in);
            in = new Scanner(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataInputStream = new DataInputStream(socket.getInputStream());
            out = new PrintWriter(socket.getOutputStream(), true);
            out.println("sendpublickey");
            String ServerPublicKeyString = in.nextLine();
            String SignedCertificate = in.nextLine();
            String data = "Domain:PasswordManager.com\n"+"Public Key:"+ServerPublicKeyString;
            if (!ca.verify(data,SignedCertificate))
                System.out.println("Failed in verifying certificate");
            else{
                PublicKey ServerPublicKey = ASymmetric.string2PublicKey(ServerPublicKeyString);
                symmetric.generateKey();
                out.println(   ASymmetric.encryptMessage(symmetric.getKey(),ServerPublicKey)   );
                System.out.println(in.nextLine());
                symmetric.START(symmetric.getKey());
                while (scanner.hasNextLine()) {

                    String requestToSend = scanner.nextLine();
                    String[] requestParts = getRequestParts(requestToSend);

                    if (requestParts[0].equals("sendtouser")){
                        sendToUserHandler(requestParts);
                        continue;
                    }

                    if (requestParts[0].equals("addpassword") || requestParts[0].equals("editpassword"))
                        requestToSend = EncryptPassword(requestParts);

                    SEND(requestToSend);
                    System.out.println("request HAS SENT");

                    if (requestParts[0].equals("createuser")) {
                        ASymmetric.init();
                        SEND("\"" + ASymmetric.getPublicKeyAsString() + "\"");
                        String clientDC = ca.Sign( CSR(requestParts[1].substring(1,requestParts[1].length()-1),ASymmetric.getPublicKeyAsString()) );
                        SEND(clientDC);
                    }

                    String response = RECEIVE();

                    if (response.startsWith("name="))
                        response = HandleShowPasswordResponse(response);

                    System.out.println(response);

                    if (requestParts[0].equals("createuser") && response.equals("User Created"))
                        StorePublicAndPrivate(requestParts[1]);

                    if (requestParts[0].equals("login") && response.equals("Operation Succeeded")) {
                        isLoggedIn = true;
                        GetPublicAndPrivate(requestParts[1]);
                        getSharedPassword();

                    }

                    if (requestParts[0].equals("logout") && response.equals("Operation Succeeded"))
                        isLoggedIn = false;




                    if (requestParts[0].equals("sendfile") && response.equals("Operation Succeeded"))
                        storeFile("received", getFileExtension(requestParts[1].substring(1, requestParts[1].length() - 1)));

                    if (response.equals("Enter File Path")) {
                        sendFile(scanner.nextLine());
                        String Response = RECEIVE();
                        System.out.println(Response);
                    }
                }
                }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static String CSR(String Client,String PK){
        String s = "Client:"+Client+"\n";
        s+="Public Key:"+PK;
        return s;
    }

    public static void getSharedPassword(){
        while (true){
            String senderPK = RECEIVE();
            if (senderPK.equals("END"))
                break;
            System.out.println(RECEIVE());
            String encrypted = RECEIVE();
            String signed = RECEIVE();
            String decrypted = checkSignAndDec(encrypted,senderPK,signed);
            System.out.println(decrypted);
            System.out.println(RECEIVE());
            String req = scanner.nextLine();
            if (req.equals("y")){
                req = "y "+decrypted;
                req = EncryptPassword(getRequestParts(req));
            }
            SEND(req);
            if (getRequestParts(req)[0].equals("y"))
                System.out.println(RECEIVE());
        }
        System.out.println("END");
    }

    public static String checkSignAndDec(String data,String senderPK,String signed){
        if (!ASymmetric.verifySignature(data,ASymmetric.string2PublicKey(senderPK),signed))
            return "Signature Verification Failed!!";
        return ASymmetric.decryptMessage(data,null);
    }

    public static String shortenPassword(String s){
        String res="";
        String[] parts=s.split(",");
        for (int i=0;i<5;i++){
            res+="\"";
            int j=0;
            while (j!=parts[i].length()&&parts[i].charAt(j)!='=')
                j++;
            j++;
            while (j!=parts[i].length()) res+=parts[i].charAt(j++);
            res+="\" ";
        }
        return res;
    }
    // sendtouser "facebok" "ahmed"
    public static void sendToUserHandler(String[] requsetParts){
        String passwordName = requsetParts[1];
        SEND("showpassword "+passwordName);
        String password = RECEIVE();
        if (!password.startsWith("name=")) {
            System.out.println(password);
            return;
        }
        password = HandleShowPasswordResponse(password);
        password = shortenPassword(password);
        SEND("getuserpublickey "+requsetParts[2]);
        String toPub = RECEIVE();
        if (toPub.equals("No such user exists") || toPub.equals("SQL ERROR")){
            System.out.print(toPub);
            return;
        }
        String enc = ASymmetric.encryptMessage(password,ASymmetric.string2PublicKey(toPub));
        String signed = "\""+ASymmetric.sign(enc)+"\"";
        enc = "\""+enc+"\"";
        SEND("sendtouser "+enc+" "+requsetParts[2]+" "+signed);
        System.out.println(RECEIVE());
    }

    public static String HandleShowPasswordResponse(String res){
        int i=0;
        String ret="";
        String encrypted = "";
        while (i<res.length())
        {
            ret+=res.charAt(i);
            if (res.charAt(i) == '=' && res.charAt(i-1)=='d'){
                i++;
                while (i<res.length() && res.charAt(i)!=',')
                    encrypted+=res.charAt(i++);
                ret+=ASymmetric.decryptMessage(encrypted,null);
                ret+=',';
            }
            i++;
        }
        return ret;
    }

    public static String getString(String [] s){
        String ret=s[0]+" ";
        for (int i=1;i<s.length-1;i++)
            ret+=s[i]+" ";
        ret+=s[s.length-1];
        return ret;
    }

    public static String EncryptPassword(String [] requestParts){
        int i=0;
        if (requestParts[0].equals("addpassword") || requestParts[0].equals("y"))
            i=3;
        else {
            if (requestParts[4].equals("\"-\""))
                return getString(requestParts);
            else i=4;
        }
        requestParts[i] = "\""+ASymmetric.encryptMessage(requestParts[i].substring(1,requestParts[i].length()-1),null)+"\"";
        return getString(requestParts);
    }


    public static void StorePublicAndPrivate(String username){
        try {
            username = username.substring(1,username.length()-1);
            new File("C://Users//Asus//IdeaProjects//ClientSide//users//"+username).mkdir();
            File Public = new File("users/"+username+"/public.txt");
            File Private = new File("users/"+username+"/private.txt");
            FileWriter myWriter = new FileWriter(Public);
            myWriter.write(ASymmetric.getPublicKeyAsString());
            myWriter.close();
            myWriter = new FileWriter(Private);
            myWriter.write(ASymmetric.getPrivateKeyAsString());
            myWriter.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void GetPublicAndPrivate(String username){
        try {
            username = username.substring(1,username.length()-1);
            File f = new File("users/"+username+"/public.txt");
            FileReader fr = new FileReader(f);
            int i;
            String publicK = "";
            while ((i = fr.read()) != -1)
                publicK += (char) i;
            f = new File("users/"+username+"/private.txt");
            fr = new FileReader(f);
            String privateK = "";
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


    public static void sendFile(String Filepath){
        if (symmetric.getmustEnc())
            out.println(symmetric.initIV());
        try {
            File f = new File (Filepath);
            File myFile = new File("Files/decrypted"+getFileExtension(Filepath));
            symmetric.encFile(f,myFile);
            int bytes = 0;
            FileInputStream fileInputStream = new FileInputStream(myFile);
            dataOutputStream.writeLong(myFile.length());
            byte[] buffer = new byte[4*1024];
            while ((bytes=fileInputStream.read(buffer))!=-1){
                dataOutputStream.write(buffer,0,bytes);
                dataOutputStream.flush();
            }
            fileInputStream.close();
            myFile.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void storeFile(String name,String type){
        if (symmetric.getmustEnc())
            symmetric.setIv(in.nextLine());
        try {
            int bytes = 0;
            FileOutputStream fileOutputStream = new FileOutputStream("Files/decrypted"+name+type);
            long size = dataInputStream.readLong();
            byte[] buffer = new byte[4*1024];
            while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
                fileOutputStream.write(buffer,0,bytes);
                size -= bytes;
            }
            fileOutputStream.close();
            File f= new File("Files/decrypted"+name+type);
            File myFile = new File("Files/"+name+type);
            symmetric.decFile(f,myFile);
            f.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String[] getRequestParts(String request){
        String res[] = new String[15];
        int i=0,j=1;
        while (i<request.length() && request.charAt(i)!=' ')
            i++;
        res[0]=request.substring(0,i);
        i++;
        while (i<request.length()){
            int c=0;
            int st = i;
            while (i<request.length() && c!=2){
                if (request.charAt(i)=='\"')
                    c++;
                i++;
            }
            res[j++]=request.substring(st,i);
            i++;
        }
        return res;
    }

    public static String getFileExtension(String path){
        int i=path.length()-1;
        while (path.charAt(i)!='.')
            i--;
        return path.substring(i);
    }

    public static void SEND(String Response){
        // Send IV
        if (symmetric.getmustEnc())
            out.println(symmetric.initIV());
        // Send Response
        String encrypted = symmetric.enc(Response);
        out.println(encrypted);
        // Send MAC
        if (isLoggedIn){
            out.println( ASymmetric.sign(encrypted) );
        }
        else{
            if (symmetric.getmustEnc())
                out.println(symmetric.MAC(encrypted));
        }
    }

    public static String RECEIVE(){
        // Recieve IV
        if (symmetric.getmustEnc())
            symmetric.setIv(in.nextLine());
        // Recieve Request
        String encrypted = in.nextLine();
        String decrypted = symmetric.dec( encrypted );
        // Recieve MAC
        if (symmetric.getmustEnc()){
            String receivedMac = in.nextLine();
            String calculatedMac = symmetric.MAC(encrypted);
            if (!receivedMac.equals(calculatedMac)) return "MAC NOT MATCH";
        }
        return decrypted;
    }
}
// login "omar" "1122334455667788"
// login "moh" "123"
// C://Users//Asus//Desktop//file.txt
// sendfile "Files/facebook7.txt"
// showpassword "facebook"
// addpassword "steam" "omar" "3312" "this is codeforces password" ".txt"
// Domain: passwordManager.com
// Client: ahmed