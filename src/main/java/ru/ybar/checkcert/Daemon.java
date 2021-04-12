/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ru.ybar.checkcert;

import java.awt.AWTException;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTable;
import javax.swing.SwingUtilities;

/**
 *
 * @author slawka
 */
public class Daemon implements Runnable {

    JTable jTable = null;
    private static CheckCert cert = new CheckCert();
    Boolean run = true;
    long wait = 43200000;

    public void setjTable(JTable jTable) {
        this.jTable = jTable;
    }

    public void setRun(Boolean run) {
        this.run = run;
    }

    public void setWait(long wait) {
        this.wait = wait;
    }

    public void run() {
        SystemTray tray = SystemTray.getSystemTray();

        Image image = Toolkit.getDefaultToolkit().createImage(getClass().getClassLoader().getResource("icon.png"));
        TrayIcon trayIcon = new TrayIcon(image, "Check Cert");
        trayIcon.setImageAutoSize(true);
        trayIcon.setToolTip("Check Cert");

        try {
            tray.add(trayIcon);
        } catch (AWTException ex) {
            Logger.getLogger(Daemon.class.getName()).log(Level.SEVERE, null, ex);
        }

        while (run) {
            try {
                Thread.sleep(wait);
            } catch (InterruptedException ex) {
                Logger.getLogger(Daemon.class.getName()).log(Level.SEVERE, null, ex);
                Thread.currentThread().interrupt();
            }
            if (!cert.getEndOfDay().equals("")) {
                trayIcon.displayMessage("WARNING ", cert.getEndOfDay(), MessageType.WARNING);
            }
            jTable.setModel(cert.listCertTable());
            jTable.invalidate();

            Logger.getLogger(Daemon.class.getName()).log(Level.INFO, "Read DB");
        }
    }
}
