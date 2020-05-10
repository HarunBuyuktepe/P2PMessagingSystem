package com.CSE4057.ObjectInputOutputStreamExample;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;


public class NewServer {

    private static Key privateKeyOfServer = null;
    private static Key publicKeyOfServer = null;
    private static HashMap clientInfo = null;
    NewServer(Key privateKeyOfServer , Key publicKeyOfServer ,HashMap clientInfo){
        this.privateKeyOfServer =privateKeyOfServer;
        this.publicKeyOfServer = publicKeyOfServer;
        this.clientInfo = clientInfo;
    }

    public static void main(String[] args) throws Exception {
        // don't need to specify a hostname, it will be the current machine
        NewServer newServer = new NewServer(privateKeyOfServer,publicKeyOfServer,clientInfo);
        generateKey();
        clientInfo = new HashMap();
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
    public static Key getPrivateKeyOfServer(){return privateKeyOfServer;}
    public static Key getPublicKeyOfServer(){return publicKeyOfServer;}
    public static void setPrivateKeyOfServer(Key k){privateKeyOfServer=k;}
    public static void setPublicKeyOfServer(Key k){publicKeyOfServer=k;}

    public static void addToHash(byte[] certificate, String userNameOfClient) {
        getClientInfo().put(userNameOfClient,certificate);
    }
    public static HashMap getClientInfo(){return clientInfo;}

    public static void generateKey() throws Exception {
        // here we generate server keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        setPrivateKeyOfServer(kp.getPrivate());
        setPublicKeyOfServer(kp.getPublic());
    }
}

// ClientHandler class
class ClientHandler extends Thread
{
//    final ObjectInputStream ois;
//    final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    Key publicKeyOfClient = null;
    String userNameOfClient = null;
    Key privateKeyOfServer = null;
    Key publicKeyOfServer = null;
    byte[] certificate = null;
    Boolean sendedCertificate = false;
    NewServer newServer = null;
    // Constructor
    public ClientHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream, NewServer newServer) {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.newServer = newServer;
        this.privateKeyOfServer = newServer.getPrivateKeyOfServer();
        this.publicKeyOfServer = newServer.getPublicKeyOfServer();
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;
        try {
            objectOutputStream.writeObject(publicKeyOfServer);
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
                        saveCertificate(certificate,userNameOfClient);
                        sendedCertificate = true;
                    } else if(stringComing.equals("not verified certificate")){
                        sendedCertificate = false;
                        System.out.println("Cerfication can not verified... Now again certification process will work");
                    } else if(stringComing.contains("send all peers")){
                        //we will send all
                        System.out.println("liste ver la ok vermiş");
                        objectOutputStream.writeObject(newServer.getClientInfo());
                        newServer.getClientInfo().forEach((key, value) -> {
                            System.out.println(key+" "+Base64.getEncoder().encodeToString((byte[]) value));
                        });
                        System.out.println(newServer.getClientInfo());
                    } else {
                        if(userNameOfClient==null){
                            userNameOfClient = stringComing;
                            System.out.println("Loooooooo "+userNameOfClient);
                        } else {
                            objectOutputStream.writeObject(new String("wrong command"));
                        }


                    }
                    System.out.println(stringComing);

                }
                if(!sendedCertificate && userNameOfClient != null && publicKeyOfClient != null){
                    System.out.println("sending certificate");
                    certificate = certificate(publicKeyOfClient,privateKeyOfServer);
                    objectOutputStream.writeObject(certificate);
                }

            }catch (Exception e){
                System.out.println("hata");
                return;
            }
        }


    }

    private void saveCertificate(byte[] certificate, String userNameOfClient) {
//        bir yere save etmeli
        newServer.addToHash(certificate,userNameOfClient);
    }

    public byte[] certificate(Key publicKeyOfClient, Key privateKeyOfServer) throws Exception {
        // here we sign public key of client with server private key
        Signature certificate=Signature.getInstance("SHA256withRSA");
        certificate.initSign((PrivateKey) privateKeyOfServer);
        certificate.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());
        byte[] digitalSign = certificate.sign();
        return digitalSign; // return digital signature
    }
}
