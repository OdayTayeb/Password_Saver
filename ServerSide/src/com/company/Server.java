package com.company;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

public class Server implements Runnable {
    private Socket socket;
    private Scanner in;
    private PrintWriter out;
    private Statement sql;
    private int LoggedInUserId = -1;
    private PublicKey LoggedInPublicKey;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private Symmetric symmetric = new Symmetric();
    private String SignedCertificate;
    private CA ca;

    Server(Socket socket,String s,CA ca) {
        this.socket = socket;
        this.ca =ca;
        SignedCertificate = s;
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwordmanager", "root", "mysql");
            sql = connection.createStatement();
        }
        catch (Exception e){
            System.out.println(e);
        }
    }
    @Override
    public void run() {
        System.out.println("Connected: " + socket);
        try {
            dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataInputStream = new DataInputStream( socket.getInputStream() );
            in = new Scanner(socket.getInputStream());
            out = new PrintWriter(socket.getOutputStream(), true);
            HandleSocket();
        } catch (Exception e) {
            System.out.println("Error:" + socket);
        }
        finally {
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Closed: " + socket);
        }
    }

    public void HandleSocket(){
        while (in.hasNextLine())
        {
            String request = RECEIVE();
            System.out.println("Request: "+request);

            String[] requestParts = getRequestParts(request);
            if (requestParts[0].equals("sendpublickey"))
                sendPublicKeyResponse();
            if (requestParts[0].equals("createuser"))
                createUserResponse(requestParts[1], requestParts[2],RECEIVE(),RECEIVE());
            if (requestParts[0].equals("login"))
                loginResponse(requestParts[1], requestParts[2]);
            if (requestParts[0].equals("logout"))
                logoutResponse();
            if (requestParts[0].equals("addpassword"))
                addPasswordResponse(requestParts[1],requestParts[2],requestParts[3],requestParts[4],requestParts[5]);
            if (requestParts[0].equals("showpassword"))
                showPasswordResponse(requestParts[1]);
            if (requestParts[0].equals("deletepassword"))
                deletePasswordResponse(requestParts[1]);
            if (requestParts[0].equals("editpassword"))
                editPasswordResponse(requestParts[1],requestParts[2],requestParts[3],requestParts[4],requestParts[5],requestParts[6]);
            if (requestParts[0].equals("sendfile"))
                sendFileResponse(requestParts[1]);
            if (requestParts[0].equals("getuserpublickey"))
                getUserPublicKeyResponse(requestParts[1]);
            if (requestParts[0].equals("sendtouser"))
                sendToUserResponse(requestParts[1],requestParts[2],requestParts[3]);
        }
    }

    /// name "par1" "par2"
    // createuser "ahmed" "123"

    public String[] getRequestParts(String request){
        String res[] = new String[15];
        int i=0,j=1;
        while (i<request.length() &&request.charAt(i)!=' ')
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

    public void sendPublicKeyResponse(){
        String response="",response2="";
        response=ASymmetric.getPublicKeyAsString();
        out.println(response);
        out.println(SignedCertificate);
        String key = ASymmetric.decryptMessage( in.nextLine(),null);
        response2="Session Key Received";
        out.println(response2);
        symmetric.START(key);
    }

    public void createUserResponse(String name,String password,String Publickey,String clientCertificate) {
        String response="";
        try{
            String data ="Client:"+name.substring(1,name.length()-1)+"\n"+"Public Key:"+Publickey.substring(1,Publickey.length()-1);
            if (!ca.verify(data,clientCertificate)) response = "Failed in verifying certificate";
            else{
                ResultSet resultSet = sql.executeQuery("SELECT * FROM user where name="+name);
                if (resultSet.next())
                    response = "User exists already";
                else {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(password.substring(1,password.length()-1).getBytes(StandardCharsets.UTF_8));
                    password = "\"" + Base64.getEncoder().encodeToString(hash)+"\"";
                    sql.executeUpdate("INSERT INTO user (name,password,publickey) VALUES ("+name+","+password+","+Publickey+")");
                    response = "User Created";
                }
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }finally {
            SEND(response);
        }
    }

    public void loginResponse(String name,String password){
        String response = "";
        response = "You Are Logged In Already.You must Logout to change your account";
        try{
            if (LoggedInUserId == -1) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(password.substring(1,password.length()-1).getBytes(StandardCharsets.UTF_8));
                password = "\"" + Base64.getEncoder().encodeToString(hash)+"\"";
                ResultSet resultSet = sql.executeQuery("SELECT * FROM user where name=" + name + " AND password=" + password);
                if (resultSet.next()) {
                    LoggedInUserId = resultSet.getInt(1);
                    LoggedInPublicKey = ASymmetric.string2PublicKey( resultSet.getString(4) );
                    response = "Operation Succeeded";
                } else
                    response = "Invalid username or password";
            }
            else response = "You Are Logged In Already.You must Logout to change your account";
        }catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }finally {
            SEND(response);
            if (response.equals("Operation Succeeded"))
                SendSharedPasswordToUser();
        }
    }

    public void SendSharedPasswordToUser(){
        try {
            boolean Has = false;
            ResultSet resultSet = sql.executeQuery("SELECT * FROM share where userId=" + LoggedInUserId);
            ArrayList<String> S,M,P;
            S=new ArrayList<>();
            M=new ArrayList<>();
            P=new ArrayList<>();
            while (resultSet.next()){
                S.add(resultSet.getString(5));
                M.add(resultSet.getString(2));
                P.add(resultSet.getString(4));
            }
            for (int i=0;i<S.size();i++) {
                Has = true;
                String signed = S.get(i);
                String message = M.get(i);
                String pk = P.get(i);
                ResultSet r1 = sql.executeQuery("SELECT * FROM user where publickey="+"\""+pk+"\"");
                r1.next();
                SEND(pk);
                SEND("user " + r1.getString(2) + " suggests password ");
                SEND(message);
                SEND(signed);
                SEND("if you want to add it to your passwords enter 'y' else enter 'n'");
                String res = RECEIVE();
                String[] resParts = getRequestParts(res);
                if (resParts[0].equals("y"))
                    addSharedPassword(resParts[1], resParts[2], resParts[3], resParts[4], resParts[5]);
            }
            if (Has)
                sql.executeUpdate("DELETE FROM share where userId="+LoggedInUserId);
            SEND("END");
        }
        catch (Exception e){
            e.printStackTrace();
        }

    }

    public void addSharedPassword(String name,String user,String password,String description,String original){
        String response = "";
        try{
            String path = "\"Files/"+name.substring(1,name.length()-1)+LoggedInUserId+getFileExtension(original.substring(1,original.length()-1))+"\"";
            Files.copy(Paths.get(original.substring(1,original.length()-1)),Paths.get(path.substring(1,path.length()-1)),StandardCopyOption.REPLACE_EXISTING);
            ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where name=" + name +" AND userId="+LoggedInUserId);
            if (resultSet.next())
                response = "the title of the password is already exists";
            else {
                sql.executeUpdate("INSERT INTO passwords (name,user,password,description,filepath,userId) VALUES (" + name + "," + user + "," + password + "," + description + "," + path + "," + LoggedInUserId + ")");
                response = "Operation Succeeded";
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            SEND(response);
        }
    }

    public void logoutResponse(){
        String response = "Operation Succeeded";
        if (LoggedInUserId == -1){
            response = "You Are not Logged In";
        }
        else {
            LoggedInUserId = -1;
        }
        SEND(response);
    }

    // addpassword "name" "user" "password" "des" ".txt"
    public void addPasswordResponse(String name,String user,String password,String description,String type){
        String response = "",fileResponse="";
        try {
            if (LoggedInUserId == -1)
                response = "You Are Not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where name=" + name +" AND userId="+LoggedInUserId);
                if (resultSet.next())
                    response = "the title of the password is already exists";
                else {
                    fileResponse = "Enter File Path";
                    SEND(fileResponse);
                    String path = storeFile(name.substring(1,name.length()-1),type);
                    sql.executeUpdate("INSERT INTO passwords (name,user,password,description,filepath,userId) VALUES (" + name + "," + user + "," + password + "," + description + "," + path + "," + LoggedInUserId + ")");
                    response = "Operation Succeeded";
                }
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL Error";
        }finally {
            SEND(response);
        }
    }

    public void showPasswordResponse(String name){
        String response="";
        try {
            if (LoggedInUserId == -1)
                response = "You Are Not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where name=" + name +" AND userId="+LoggedInUserId);
                if (resultSet.next())
                    response = "name="+resultSet.getString(2)+", username or email="+resultSet.getString(3)+", password="+resultSet.getString(4)+", Description="+resultSet.getString(5)+", file path="+resultSet.getString(6);
                else response = "No such Password element exists";
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }
        finally {
            SEND(response);
        }
    }

    public void deletePasswordResponse(String name){
        String response="";
        try {
            if (LoggedInUserId == -1)
                response = "You Are Not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where name=" + name +" AND userId="+LoggedInUserId);
                if (resultSet.next()) {
                    String path = resultSet.getString(6);
                    sql.executeUpdate("DELETE FROM passwords WHERE name="+name);
                    File f=new File(path);
                    f.delete();
                    response = "Operation Succeeded";
                }
                else response = "No such Password element exists";
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }
        finally {
            SEND(response);
        }
    }

    public void editPasswordResponse(String wanted,String name,String user,String password,String description,String type){
        String response = "",fileResponse="";
        try {
            if (LoggedInUserId == -1)
                response = "You Are Not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where name=" + wanted +" AND userId="+LoggedInUserId);
                if (resultSet.next()){
                    String path = "\""+resultSet.getString(6)+"\"";
                    if (name.equals("\"-\"")) name = "\""+ resultSet.getString(2)+"\"";
                    if (user.equals("\"-\"")) user = "\""+resultSet.getString(3)+"\"";
                    if (password.equals("\"-\"")) password = "\""+resultSet.getString(4)+"\"";
                    if (description.equals("\"-\"")) description = "\""+resultSet.getString(5)+"\"";
                    if (!type.equals("\"-\"")) {
                        File f=new File(path.substring(1,path.length()-1));
                        f.delete();
                        fileResponse = "Enter File Path";
                        out.println(fileResponse);
                        path = storeFile(name.substring(1, name.length() - 1), type);
                    }
                    sql.executeUpdate("UPDATE passwords SET name="+ name +",user="+user+",password="+password+",description="+description+",filepath="+path+" WHERE name="+wanted);
                    response = "Operation Succeeded";
                }
                else response = "No such Password element exists";
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL Error";
        }finally {
            SEND(response);
        }
    }

    public void sendFileResponse(String path){
        String response="";
        try {
            if (LoggedInUserId == -1)
                response = "You Are Not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM passwords where filepath=" + path +" AND userId="+LoggedInUserId);
                if (resultSet.next()) {
                    response = "Operation Succeeded";
                }
                else response = "No such file element exists";
            }
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }
        finally {
            SEND(response);
            if (response.equals("Operation Succeeded"))
                sendFile(path.substring(1,path.length()-1));
        }
    }

    public void getUserPublicKeyResponse(String name){
        String response="";
        try {
            ResultSet resultSet = sql.executeQuery("SELECT * FROM user where name=" + name);
            if (resultSet.next())
                response = resultSet.getString(4);
            else response = "No such user exists";
        }
        catch (Exception e){
            System.out.println(e);
            response = "SQL ERROR";
        }
        finally {
            SEND(response);
        }
    }

    public void sendToUserResponse(String message,String name,String signed){
        String response="";
        try {
            if (LoggedInUserId == -1) response = "You Are not Logged In";
            else {
                ResultSet resultSet = sql.executeQuery("SELECT * FROM user where name=" + name);
                if (resultSet.next()){
                    int to = resultSet.getInt(1);
                    ResultSet r1=sql.executeQuery("SELECT * FROM user where id=" + LoggedInUserId);
                    r1.next();
                    String senderPublicKey = "\""+ r1.getString(4) + "\"";
                    sql.executeUpdate("INSERT INTO share (data,userId,senderpublickey,sign) VALUES ("+message+","+to+","+senderPublicKey+","+signed+")");
                    response = "Operation Succeeded";
                }
                else response = "No such user exists";
            }
        }
        catch (Exception e){
            e.printStackTrace();
            response = "SQL ERROR";
        }
        finally {
            SEND(response);
        }
    }

    public String storeFile(String name,String type){
        if (symmetric.getmustEnc())
            symmetric.setIv(in.nextLine());
        type =type.substring(1,type.length()-1);
        try {
            int bytes = 0;
            FileOutputStream fileOutputStream = new FileOutputStream("Files/decrypted"+name+LoggedInUserId+type);
            long size = dataInputStream.readLong();
            byte[] buffer = new byte[4*1024];
            while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
                fileOutputStream.write(buffer,0,bytes);
                size -= bytes;
            }
            fileOutputStream.close();
            File f= new File("Files/decrypted"+name+LoggedInUserId+type);
            File myFile = new File("Files/"+name+LoggedInUserId+type);
            symmetric.decFile(f,myFile);
            f.delete();
            return "\"Files/"+name+LoggedInUserId+ type+"\"";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
    public void sendFile(String Filepath){
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

    public String getFileExtension(String path){
        int i=path.length()-1;
        while (path.charAt(i)!='.')
            i--;
        return path.substring(i);
    }

    public void SEND(String Response){
        // Send IV
        if (symmetric.getmustEnc())
            out.println(symmetric.initIV());
        // Send Response
        String encrypted = symmetric.enc(Response);
        out.println(encrypted);
        // Send MAC
        if (symmetric.getmustEnc())
            out.println(symmetric.MAC(encrypted));
    }

    public String RECEIVE(){
        // Recieve IV
        if (symmetric.getmustEnc())
            symmetric.setIv(in.nextLine());
        // Recieve Request
        String encrypted = in.nextLine();
        String decrypted = symmetric.dec( encrypted );
        // Recieve MAC
        if (LoggedInUserId != -1){
            if (!ASymmetric.verifySignature(encrypted,LoggedInPublicKey,in.nextLine()))
                return "Digital Signature Verification Failed";
        }
        else{
            if (symmetric.getmustEnc()) {
                String receivedMac = in.nextLine();
                String calculatedMac = symmetric.MAC(encrypted);
                if (!receivedMac.equals(calculatedMac)) return "MAC NOT MATCH";
            }
        }
        return decrypted;
    }
}