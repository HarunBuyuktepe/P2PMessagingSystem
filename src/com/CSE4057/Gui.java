package com.CSE4057;

import java.io.*;
import javax.swing.*;
import java.awt.event.*;

public class Gui implements ActionListener
{
	/* GUI & Other Class Objects */
    JTextField tf1;
    JLabel l1, l2;
    JButton b1;
    JPanel panel;
    JFrame f = new JFrame();
    ObjectOutputStream objectOutputStream;
    ObjectInputStream objectInputStream;
    String userName = "";
    NewClient newClient;
    Crypt crypt;
    int nonce;
    
    public Gui(String s)
    {
        crypt = new Crypt();
        f.setTitle(s);				// Frame Title

        tf1 = new JTextField();
        tf1.setBounds(60, 50, 150, 20);		// Position of Text Field

        l1 = new JLabel("First Label");
        l1.setBounds(60, 100, 100, 30);		// Position of Info Message
        l2 = new JLabel("Message");
        l2.setBounds(60, 20, 100, 30);		// Position of Text Field Title
        b1 = new JButton("Send");
        b1.setBounds(95, 150, 80, 50);		// Position of Button
        b1.addActionListener(this);

        f.add(tf1); f.add(l1); f.add(b1); f.add(l2);		// Append Labels & Button To The Frame
        f.setSize(300, 300);		// Size of Frame
        f.setLayout(null);
        f.setVisible(true);
    }
    
    public void actionPerformed(ActionEvent e)		// Button Click Event
    {
        String s1 = tf1.getText();
        if(e.getSource() == b1)
        {
            try {
                // message formatted
                String message = userName + " : - " + s1;
                // To give terminal message
                System.out.println(message);
                
                byte[] send, mac_byte;
                // Our message encrypted with creation of mac algoritm and encryption with AES key and Init Vector
                mac_byte = crypt.macAlgorithm(newClient.encryprtionKey, message.getBytes("UTF-8"));
                send = crypt.arrayConcatenate(message.getBytes("UTF-8"), mac_byte, nonce);
                // Message encrypted using CBC mode
                send = crypt.cbcBlockCipherEncrypt(send, newClient.currentCipherText, newClient.encryprtionKey, newClient.iv);
                // And we send encrypted and secured message
                objectOutputStream.writeObject(send); 		// Encrypted Message
                objectOutputStream.writeObject(newClient.currentCipherText);
                newClient.currentCipherText = send;
                tf1.setText("");
                // objectOutputStream.writeObject(userName + " : - " + s1);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            
            l1.setText("Sent it");			// Set Info Message as 'Sent It'
        }
    }
    
    public static void main(String[] args) {
        new Gui("Client 1");
    }

    public void setObjectOutputStream(ObjectOutputStream s) {
        objectOutputStream = s;
    }

    public void setObjectInputStream(ObjectInputStream s) {
        objectInputStream = s;
    }
    
    public void setL1(String m) {
        l1.setText(m);
    }
    
    public static void addPanel(JPanel panel, String s) {
        JLabel label = new JLabel(s);
        panel.add(label);
    }

    public void addToGui(String stringComing) {
        addPanel(panel, stringComing);
    }
    
    public void setUserName(String s) { userName = s; }
    
    public void setName(String name) { f.setTitle(name); }

    public void setNewClient(NewClient client) { newClient = client; }
    
    public void setNonce(int n) { nonce = n; }
    
}
