package com.CSE4057.ObjectInputOutputStreamExample;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.List;

import static com.CSE4057.ObjectInputOutputStreamExample.NewServer.*;
import static com.CSE4057.ObjectInputOutputStreamExample.NewServer.getPrivateKeyOfServer;

public class NewClient {
    public static Key pub;
    public static Key pvt;
    public static String userName="";
    public static byte[] serverCertificate = null;
    public static Key serverPublicKey = null;
    public static Boolean verifyCheck = false;
    public static boolean scannerOn;
    public static int portNumber;
    public static List<Socket> socketList = null;
    public boolean wait;

    public NewClient() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        //defined key pair; public and private and we generate new pair
        this.pub = kp.getPublic();
        this.pvt = kp.getPrivate();
        this.userName="";
        verifyCheck = false;
        this.serverCertificate = null;
        this.serverPublicKey = null;
        this.socketList =   new ArrayList<Socket>();
        System.out.println("Client generate its keys");
        boolean scannerOn=false;
        int portNumber = 0;
        this.wait = true;
    }
    public void setPublicKey(Key k){
        pub=k;
    }
    public void setPrivateKey(Key k){
        pvt=k;
    }
    public void setUserName(String name){userName=name;}
    public static Key getPublicKey(){return pub;}
    public Key getPrivateKey(){return pvt;}
    public String getUserName() {return userName;    }
    public static Key getServerPublicKey(){return serverPublicKey;}
    public static int getPortNumber(){return portNumber;}

    public static void main(String[] args) throws Exception {

        NewClient client = new NewClient();
        client.portNumber = 8035;
        ServerSocket ss = new ServerSocket(client.portNumber);
        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.println("Enter username : ");
        while(name == null  || name =="" ){
            name = scn.nextLine();
            client.setUserName(name);
        }
        System.out.println("Client ready to connect server ...");
        Socket socket = new Socket("localhost", 8018);
        client.socketList.add(socket);
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream serverObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream serverObjectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending public key and username to the ServerSocket");
        serverObjectOutputStream.writeObject(client.getPublicKey());
        serverObjectOutputStream.writeObject(client.getUserName());
        serverObjectOutputStream.writeObject(client.getPortNumber());

        int portToConnect = 0;
        HashMap allPeers=null;
        HashMap portPeers=null;
        client.scannerOn=false;
        client.wait = true;
        while (true){
            Object o = serverObjectInputStream.readObject();
            if (o instanceof byte[]){
                System.out.println("Certificate come");
                client.serverCertificate = (byte[]) o;
                client.verifyCheck = true;
            } else if (o instanceof Key){
                System.out.println("Key come");
                client.serverPublicKey = (Key) o;
                client.verifyCheck = true;
            } else if (o == null){
                System.out.println("Coming object is null");
            } else if (o instanceof HashMap){
                Crypt crypt = new Crypt();
                HashMap anyhash = (HashMap) o;
                Map.Entry entry = (Map.Entry) anyhash.entrySet().iterator().next();
                if(entry.getValue() instanceof byte[]) {
                    allPeers = anyhash;
//                    allPeers.forEach((key, value) -> {
//                        try {
//                            System.out.println("Peer : "+key + " " + crypt.decrypt((byte[]) value, getServerPublicKey()));
//                        } catch (Exception e) {
//                            e.printStackTrace();
//                        }
//                    });
                    client.wait = true;
                } else {
                    portPeers = anyhash;
                    portPeers.forEach((key, value) -> {
                        try {
                            System.out.println("Peer : "+key + " Available Port : " + value);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    client.wait = false;
                }
            } else if (o instanceof String){
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            if (client.verifyCheck && client.serverPublicKey != null && client.serverCertificate != null){
                String verify = verifySigniture(client.serverCertificate,client.serverPublicKey);
                serverObjectOutputStream.writeObject(verify);
                client.verifyCheck = false;
                client.scannerOn = true;
                client.wait = false;
            }
            if(client.scannerOn && !client.wait) {
                System.out.println("Enter your choice\n1.To get all peer certificate and username, - send all peers" +
                        "\n2.To connect user, - connect USERNAME\n3.To terminate server connection, - terminate server connection"+
                        "\n4.To terminate with port number, - terminate PORT_NUMBER");
                String command = scn.nextLine();
                if (command.contains("terminate server connection")) {
                    socket.close();
                    break;
                } 
                else if (command.contains("terminate ")){
                    int terminatePort=0;
                    try {
                        terminatePort = Integer.parseInt(command.replace("terminate ", ""));
                    } catch (Exception e){
                        System.out.println("hata");
                    }
                    System.out.println(terminatePort);
                    for (Socket s: client.socketList) {
                        if(s.getPort() == terminatePort){
                            s.close();
                            if(terminatePort == 8018) {
                                System.out.println("Program end");
                                return;
                            }
                            System.out.println("Selected port closed");
                        }
                    }
                } 
                else if (command.contains("connect ")){
                    String connect="";
                    try {
                        connect = (command.replace("connect ", ""));
                    } catch (Exception e){
                        System.out.println("hata");
                    }
                    if(portPeers!=null){
                        portToConnect = (int) portPeers.get(connect);
                        for (Socket s: client.socketList) {
                            if(s.getPort() == portToConnect){
                                s.close();
                                System.out.println("Selected port closed");
                            }
                        }
                        socket.close();
                        break;
                    }
                }
                else {
                    serverObjectOutputStream.writeObject(command);
                }

            }
        }
        if(portToConnect != 0){
            System.out.println("Port to connect : "+portToConnect);
            Socket toPeerSocket = new Socket("localhost",portToConnect);
            client.socketList.add(toPeerSocket);
            ObjectOutputStream clientObjectOutputStream = new ObjectOutputStream(toPeerSocket.getOutputStream());
            ObjectInputStream clientObjectInputStream = new ObjectInputStream(toPeerSocket.getInputStream());

            Thread t = new PeerUserOneHandler(toPeerSocket,clientObjectInputStream,clientObjectOutputStream);

            t.start();

        }
        System.out.println("Program end");
    }

    public static String verifySigniture(byte[] serverSigniture, Key serverPublicKey) throws Exception {
        String verify = "verified certificate";
        String notVerifyed ="not verified certificate";
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify((PublicKey) getServerPublicKey() );
        s.update(Base64.getEncoder().encodeToString(getPublicKey().getEncoded()).getBytes());

        if(s.verify(serverCertificate)){
            return verify;
        }else
            return notVerifyed;

    }

}
// PeerHandler class
class PeerUserOneHandler extends Thread
{
    //    final ObjectInputStream ois;
//    final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    Key publicKeyOfClient = null;
    String userNameOfClient = null;
    byte[] certificate = null;
    int portNumber = 0;


    // Constructor
    public PeerUserOneHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream) {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;
        try {
            objectOutputStream.writeObject(new String("hello"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        while (true){
            try {
                o = (Object) objectInputStream.readObject();
                if (o instanceof String){
                    System.out.println("String is brought");
                    String stringComing = (String) o;
                    System.out.println(stringComing);

                } else if(o instanceof Integer){
                    portNumber = (int) o ;
                    System.out.println(portNumber);

                }
            }catch (Exception e){

                return;
            }
        }
//            try {
//                o = (Object) objectInputStream.readObject();
//                if (o instanceof Key) {
//                    System.out.println("Key is brought");
//                    publicKeyOfClient = (Key) o;
//                    System.out.println(publicKeyOfClient);
//                } else if (o instanceof String){
//                    System.out.println("String is brought");
//                    String stringComing = (String) o;
//                    System.out.println(stringComing);
//
//                } else if(o instanceof Integer){
//                    portNumber = (int) o ;
//                    System.out.println(portNumber);
//
//                }
//            }catch (Exception e){
//
//                return;
//            }
//        }


    }

}


