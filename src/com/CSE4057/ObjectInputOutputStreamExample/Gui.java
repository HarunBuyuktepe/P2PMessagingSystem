package com.CSE4057.ObjectInputOutputStreamExample;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Gui implements ActionListener{
    JTextField tf1;
    JLabel l1,l2;
    JButton b1;
    JFrame f= new JFrame();
    ObjectOutputStream objectOutputStream ;
    ObjectInputStream objectInputStream;
    JPanel panel;
    String userName="";
    public Gui(String s){

        f.setTitle(s);

        tf1=new JTextField();
        tf1.setBounds(60,50,150,20);

        l1=new JLabel("First Label.");
        l1.setBounds(60,100, 100,30);
        l2=new JLabel("Message");
        l2.setBounds(60,20, 100,30);
        b1=new JButton("Send");
        b1.setBounds(95,150,80,50);
        b1.addActionListener(this);

//        panel = new JPanel();
//        panel.setLayout(new GridLayout(10, 1, 10, 10));
//        JScrollPane jScrollPane = new JScrollPane(panel);
//        jScrollPane.setBounds(40,210,200,300);
//        f.add(jScrollPane);


        f.add(tf1);f.add(l1);f.add(b1);f.add(l2);
        f.setSize(300,600);
        f.setLayout(null);
        f.setVisible(true);
    }
    public void actionPerformed(ActionEvent e) {
        String s1=tf1.getText();
        if(e.getSource()==b1){
            try {
                System.out.println(userName+" : - "+s1);
//                addPanel(panel,"me : - "+s1);
                objectOutputStream.writeObject(userName+" : - "+s1);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            l1.setText("Sent it");
        }

    }
    public void setName(String name){
        f.setTitle(name);
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
    public void setL1(String m){
        l1.setText(m);
    }
    public static void addPanel(JPanel panel,String s) {
        JLabel label = new JLabel(s);
        panel.add(label);
    }

    public void addToGui(String stringComing) {
        addPanel(panel,stringComing);
    }
    public void setUserName(String s){userName=s;}
}