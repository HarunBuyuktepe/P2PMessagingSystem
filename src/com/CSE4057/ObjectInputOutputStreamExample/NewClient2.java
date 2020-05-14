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
        ServerSocket ss ;
        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.println("Enter username : ");
        while (name == null || name == "") {
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

        Socket peerUserTwo;
        int portToConnect = 0;
        HashMap allPeers = null;
        HashMap portPeers = null;
        client.scannerOn = false;
        client.wait = true;
        while (true) {

            Object o = serverObjectInputStream.readObject();
            if (o instanceof byte[]) {
                System.out.println("Certificate come");
                client.serverCertificate = (byte[]) o;
                client.verifyCheck = true;
            } else if (o instanceof Key) {
                System.out.println("Key come");
                client.serverPublicKey = (Key) o;
                client.verifyCheck = true;
            } else if (o == null) {
                System.out.println("Coming object is null");
            } else if (o instanceof HashMap) {
                Crypt crypt = new Crypt();
                HashMap anyhash = (HashMap) o;
                Map.Entry entry = (Map.Entry) anyhash.entrySet().iterator().next();
                if (entry.getValue() instanceof byte[]) {
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
                            System.out.println("Peer : " + key + " Available Port : " + value);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    client.wait = false;
                }
            } else if (o instanceof String) {
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            if (client.verifyCheck && client.serverPublicKey != null && client.serverCertificate != null) {
                String verify = verifySigniture(client.serverCertificate, client.serverPublicKey);
                serverObjectOutputStream.writeObject(verify);
                client.verifyCheck = false;
                client.scannerOn = true;
                client.wait = false;
            }
            if (client.scannerOn && !client.wait) {
                System.out.println("Enter your choice\n1.To get all peer certificate and username, - send all peers" +
                        "\n2.To connect user, - connect USERNAME\n3.To terminate server connection, - terminate server connection");
                String command = scn.nextLine();
                if (command.contains("terminate server connection")) {
                    socket.close();
                    break;
                }  else if (command.contains("connect ")) {
                    String connect = "";
                    try {
                        connect = (command.replace("connect ", ""));
                    } catch (Exception e) {
                        System.out.println("hata");
                    }
                    if (portPeers != null) {
                        portToConnect = (int) portPeers.get(connect);
                        for (Socket s : client.socketList) {
                            if (s.getPort() == portToConnect) {
                                s.close();
                                System.out.println("Selected port closed");
                            }
                        }
                        System.out.println("Server connection was closed...");
                        socket.close();
                        break;
                    }
                } else {
                    serverObjectOutputStream.writeObject(command);
                }

            }
        }
        if (portToConnect != 0) {
            System.out.println("Port to connect : " + portToConnect);
            Socket toPeerSocket = new Socket("localhost", portToConnect);
            client.socketList.add(toPeerSocket);
            ObjectOutputStream clientObjectOutputStream = new ObjectOutputStream(toPeerSocket.getOutputStream());
            ObjectInputStream clientObjectInputStream = new ObjectInputStream(toPeerSocket.getInputStream());

            clientObjectOutputStream.writeObject(new String("Hello"));
            clientObjectOutputStream.writeObject(client.serverCertificate);
            clientObjectOutputStream.writeObject(new String("username "+client.getUserName()));
            clientObjectOutputStream.writeObject(client.getPublicKey());

            Thread t = new PeerUserOneHandler(toPeerSocket, clientObjectInputStream, clientObjectOutputStream,client);

            t.start();

        }
        System.out.println("Program end");
        try {
            ss = new ServerSocket(client.portNumber);
            while (true) {
                try {
                    System.out.println("Wait for any connection");
                    socket = ss.accept();
                    client.socketList.add(socket);
                    ObjectInputStream serverClientObjectInputStream = new ObjectInputStream(socket.getInputStream());
                    ObjectOutputStream serverClientObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                    Thread t = new PeerUserTwoHandler(socket, serverClientObjectInputStream, serverClientObjectOutputStream, client);
                    t.start();
                    System.out.println("Accepted");
                } catch (Exception e) {
                    System.out.println("Olmii");
                }
            }

        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println("Hata");
        }
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
    String userNameOfClient = null;
    byte[] certificateOfnewPeer = null;
    int portNumber = 0;
    NewClient client=null;
    Key publicKeyOfPeer = null;
    Key publicKeyOfPeers = null;
    int nonce=9;
    Scanner scn = new Scanner(System.in);

    // Constructor
    public PeerUserTwoHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream, NewClient client) {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.client = client;
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;
        byte[] encryptedMessage;
        boolean encryptedNonceWaiting = false;
        boolean sendOneTime = false;
        Crypt crypt = new Crypt();
        boolean connecting = false;
        boolean chatModeOn = false;
        while (true){
            try {
                o = (Object) objectInputStream.readObject();
                if(!connecting) {
                    if (o instanceof byte[]) {
                        System.out.println("Certificate is brought");
                        if (certificateOfnewPeer == null)
                            certificateOfnewPeer = (byte[]) o;
                        else if (publicKeyOfPeer == null) {
                            encryptedMessage = (byte[]) o;
                            publicKeyOfPeer = crypt.decrypt(certificateOfnewPeer, client.serverPublicKey);
//                            System.out.println("text " + Base64.getEncoder().encodeToString(encryptedMessage));
//                        System.out.println("Gelen mesaj "+Base64.getEncoder().encodeToString(encryptedMessage));
//                            System.out.println("Public Key of Client - 1 - : " + Base64.getEncoder().encodeToString(publicKeyOfPeer.getEncoded()));
//                            System.out.println("Hata altta");
                            System.out.println(crypt.decryptString(encryptedMessage, publicKeyOfPeers));
                            if (!Base64.getEncoder().encodeToString(publicKeyOfPeer.getEncoded()).equals(Base64.getEncoder().encodeToString(publicKeyOfPeers.getEncoded())))
                                System.out.println("Danger");
                            String commingMessage = "0";
//                        if(crypt.decryptString(encryptedMessage,publicKeyOfPeer) == null) {
//                            commingMessage ="9";
//                            System.out.println(commingMessage);
//                        } else
                            commingMessage = crypt.decryptString(encryptedMessage, publicKeyOfPeers);
                            int comingNonce = Integer.parseInt(commingMessage);
                            if (comingNonce == nonce) {
                                objectOutputStream.writeObject(new String("ACK"));
                                connecting = true;
                                System.out.println("Chat mode on in secure\nTo send image, - **file FILE_PATH");
                                chatModeOn = true;
                            }
                        } else {
                            encryptedMessage = (byte[]) o;
                            String commingMessage = crypt.decryptString(encryptedMessage, publicKeyOfPeer);
                            System.out.println("Coming message is :" + commingMessage);
                        }
                    } else if (o instanceof Key) {
                        publicKeyOfPeers = (Key) o;
                    } else if (o instanceof String) {
//                    System.out.println("String is brought");
                        String stringComing = (String) o;
                        System.out.println(stringComing);
                        if (stringComing.contains("username ")) {
                            userNameOfClient = stringComing.replace("username ", "");
                        }

                    }

                }

            } catch (Exception e){
                e.printStackTrace();
                System.out.println("Olmadı be");
            }
            try {
                if(userNameOfClient != "" && certificateOfnewPeer != null && !sendOneTime && !connecting) {
                    objectOutputStream.writeObject(new Integer(nonce));
                    objectOutputStream.writeObject(client.getCertificate());
                    sendOneTime = true;
                    encryptedNonceWaiting = true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try{ // bağlantı kurulduysa
                if(connecting){
                    if(o instanceof String){
                        String stringComing = (String) o;
                        System.out.println(userNameOfClient + " : - " + stringComing);
                    }

                    if(chatModeOn){
                        System.out.print("me : - ");
                        String chat =  scn.nextLine();
                        if(chat.contains("**file")){
                            String path = chat.replace("**file","");
                        }
                        else
                            objectOutputStream.writeObject(chat);
                    }

                }
            } catch (Exception e){

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



