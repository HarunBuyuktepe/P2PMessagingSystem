package com.CSE4057.ObjectInputOutputStreamExample;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

import static com.CSE4057.ObjectInputOutputStreamExample.NewClient.verifySigniture;

public class NewClient2 {


    public static void main(String[] args) throws Exception {

        NewClient client = new NewClient();
        client.portNumber = 8034;
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


}
// PeerHandler class
class PeerUserTwoHandler extends Thread
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
    public PeerUserTwoHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream) {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;
        while (true){
            try {
                o = (Object) objectInputStream.readObject();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
//        try {
//            objectOutputStream.writeObject(getPublicKeyOfServer());
//        } catch (IOException e) {
//            System.out.println("Sending public key of server");
//        }
//        while (true){
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



