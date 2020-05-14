package com.CSE4057;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

import static com.CSE4057.ObjectInputOutputStreamExample.NewServer.*;
import static com.CSE4057.ObjectInputOutputStreamExample.NewServer.getClientInfo;
import static com.CSE4057.ObjectInputOutputStreamExample.NewServer.getClientPortInfo;

public class Client2
{
    private static Key privateKeyOfServer = null;
    private static Key publicKeyOfServer = null;
    private static HashMap clientInfo = null;
    private static HashMap clientPortInfo = null;

    public static void main(String[] args) throws Exception
    {    
    	// don't need to specify a hostname, it will be the current machine
        Client2 newServer = new Client2();

        generateKey();

        clientInfo = new HashMap();
        clientPortInfo = new HashMap();
        ServerSocket ss = new ServerSocket(8018);
        System.out.println("ServerSocket awaiting connections...");

        while (true) {
            Socket s = null;

            try {
                s = ss.accept(); // blocking call, this will wait until a connection is attempted on this port.
                System.out.println("A new client is connected : " + s.getPort());

                System.out.println("Assigning new thread for this client");
                ObjectInputStream objectInputStream=new ObjectInputStream(s.getInputStream());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(s.getOutputStream());
                // create a new thread object
                Thread t = new ClientHandler(s,objectInputStream,objectOutputStream,newServer);

                t.start();

            } catch (Exception e) {
                System.out.println("olmii");
            }
        }

    }
    
    public static Key getPrivateKeyOfServer() { return privateKeyOfServer; }
    public static Key getPublicKeyOfServer() { return publicKeyOfServer; }
    
    public static void setPrivateKeyOfServer(Key k) { privateKeyOfServer = k; }
    public static void setPublicKeyOfServer(Key k) { publicKeyOfServer = k; }

    public static void addToHash(String userNameOfClient, byte[] Certificate) { getClientInfo().put(userNameOfClient,Certificate); }

    public static HashMap getClientInfo() { return clientInfo; }

    public static HashMap getClientPortInfo() { return clientPortInfo; }

    public static void generateKey() throws Exception
    {
        // here we generate server keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("Public Key : " + Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
        setPrivateKeyOfServer(kp.getPrivate());
        setPublicKeyOfServer(kp.getPublic());
    }
}

// ClientHandler class
class ClientHandler extends Thread
{
	// final ObjectInputStream ois;
	// final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    Key publicKeyOfClient = null;
    String userNameOfClient = null;
    byte[] certificate = null;
    Boolean sendedCertificate = false;
    Client2 newServer = null;
    int portNumber = 0;
    
    // Constructor
    public ClientHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream, Client2 newServer){
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.newServer = newServer;
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;
        try {
            objectOutputStream.writeObject(getPublicKeyOfServer());
        } catch (IOException e) {
            System.out.println("Sending public key of server");
        }
        while (true){
            try {
                o = (Object) objectInputStream.readObject();
                if (o instanceof Key) {
                    System.out.println("Key is brought");
                    publicKeyOfClient = (Key) o;
                    sendedCertificate = false;
                    System.out.println(publicKeyOfClient);
                } else if (o instanceof String){
                    System.out.println("String is brought");
                    String stringComing = (String) o;
                    if(stringComing.equals("verified certificate")){
                        saveCertificate(userNameOfClient);
                        sendedCertificate = true;
                    } else if(stringComing.equals("not verified certificate")){
                        sendedCertificate = false;
                        System.out.println("Cerfication can not verified... Now again certification process will work");
                    } else if(stringComing.contains("send all peers")){
                        //we will send all
                        System.out.println("liste ver la ok vermiþ");

                        objectOutputStream.writeObject(newServer.getClientInfo());
                        objectOutputStream.writeObject(newServer.getClientPortInfo());
                        getClientInfo().forEach((key, value) -> {
                            System.out.println(key+" "+Base64.getEncoder().encodeToString((byte[]) value));
                        });
                    }
                    else {
                        if(userNameOfClient==null){
                            userNameOfClient = stringComing;
                            System.out.println("User name of the current client :  "+userNameOfClient);
                        } else {

                            objectOutputStream.writeObject(new String("wrong command is "+stringComing));
                        }

                    }
                    System.out.println(stringComing);

                } else if(o instanceof Integer){
                    portNumber = (int) o ;
                    System.out.println(portNumber);
                    savePort(userNameOfClient,portNumber);
                    sendedCertificate = false;
                }
                if(!sendedCertificate && userNameOfClient != null && publicKeyOfClient != null && portNumber !=0){
                    System.out.println("sending certificate");
                    certificate = certificate(publicKeyOfClient,getPublicKeyOfServer());
                    System.out.println("Sertifika uzunluðu "+certificate.length);
                    objectOutputStream.writeObject(certificate);
                }

            }catch (Exception e){
            	// getClientInfo().remove(userNameOfClient);
            	// getClientPortInfo().remove(userNameOfClient);
                return;
            }
        }


    }
    private void savePort(String userNameOfClient, int port) { getClientPortInfo().put(userNameOfClient,port ); }
    
    private void saveCertificate(String userNameOfClient) throws Exception {
    	// bir yere save etmeli
    	// System.out.println(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));
        Crypt crypt = new Crypt();
        byte[] cipherText = crypt.encrypt(publicKeyOfClient,getPrivateKeyOfServer());
        newServer.addToHash(userNameOfClient,cipherText );
    }

    public byte[] certificate(Key publicKeyOfClient, Key privateKeyOfServer) throws Exception {
        // here we sign public key of client with server private key
        Crypt crypt = new Crypt();
        byte[] cipherText = crypt.encrypt(publicKeyOfClient,getPrivateKeyOfServer());
        return cipherText; // return digital signature
    }
    
}
