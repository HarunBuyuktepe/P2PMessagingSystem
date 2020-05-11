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
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending public key and username to the ServerSocket");
        objectOutputStream.writeObject(client.getPublicKey());
        objectOutputStream.writeObject(client.getUserName());
        objectOutputStream.writeObject(client.getPortNumber());


        HashMap allPeers=null;
        HashMap portPeers=null;
        client.scannerOn=false;
        Socket peerUserTwo = null;
        while (true){
            peerUserTwo = ss.accept();
            if(socket!=null){
                client.socketList.add(socket);
                ObjectInputStream serverObjectInputStream=new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream serverObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                Thread t = new PeerUserTwoHandler(socket,serverObjectInputStream,serverObjectOutputStream);
                t.start();
            }


            Object o = objectInputStream.readObject();
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
                    allPeers.forEach((key, value) -> {
                        try {
                            System.out.println("Peer : "+key + " " + crypt.decrypt((byte[]) value, client.getServerPublicKey()));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                } else {
                    portPeers = anyhash;
                    portPeers.forEach((key, value) -> {
                        try {
                            System.out.println("Peer : "+key + " Available Port : " + value);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                }
            } else if (o instanceof String){
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            if (client.verifyCheck && client.serverPublicKey != null && client.serverCertificate != null){
                String verify = client.verifySigniture(client.serverCertificate,client.serverPublicKey);
                objectOutputStream.writeObject(verify);
                client.verifyCheck = false;
                client.scannerOn = true;
            }
            if(client.scannerOn) {
                System.out.println("Enter your choice\n1.To get all peer certificate and username, - send all peers" +
                        "\n2.To get user port, - get port USERNAME\n3.To terminate server connection, - terminate server connection"+
                        "\n4.To terminate with port number, - terminate PORT_NUMBER"+
                        "\n5.Open connection to port, open PORT_NUMBER ");
                String command = scn.nextLine();
                if (command.contains("terminate server connection")) {
                    socket.close();
                    break;
                } else if (command.contains("terminate ")){
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
                else {
                    objectOutputStream.writeObject(command);
                }

            }
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



