package com.CSE4057.BackupDosyalari;

import java.awt.*;
import javax.swing.*;
public class Scroll extends JFrame {
    public Scroll() {
        setTitle("JScrollablePanel Test");
        setLayout(new BorderLayout());
        JPanel panel = new JPanel();
        createPanel(panel,"harun");
        createPanel(panel,"harun|\n");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        createPanel(panel,"harun");
        panel.setLayout(new GridLayout(10, 4, 10, 10));
        add(new JScrollPane(panel));
        setSize(375, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setVisible(true);
    }
    public static void createPanel(JPanel panel,String s) {


        JLabel label = new JLabel(s);
        panel.add(label);


    }
    public static void main(String [] args) {
        new Scroll();
    }
}