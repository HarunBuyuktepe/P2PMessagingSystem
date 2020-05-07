package com.CSE4057.ObjectInputOutputStreamExample;


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.cert.Certificate;
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

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // don't need to specify a hostname, it will be the current machine
        NewServer newServer = new NewServer(privateKeyOfServer,publicKeyOfServer,clientInfo);
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

    public static void addToHash(Certificate certificate, String userNameOfClient) {
        getClientInfo().put(userNameOfClient,certificate);
    }
    public static HashMap getClientInfo(){return clientInfo;}

    public Key generatePrivateKey(){
        //
        return null;
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
    Certificate certificate = null;
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
                        System.out.println(newServer.getClientInfo().toString());
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

    private void saveCertificate(Certificate certificate, String userNameOfClient) {
//        bir yere save etmeli
        newServer.addToHash(certificate,userNameOfClient);
    }

    public Certificate certificate(Key publicKeyOfClient, Key privateKeyOfServer){
        //kral burada imzalatırsın
        Certificate certificate=null;

        return certificate;//bize buradan sertifika dönsün
    }
}
