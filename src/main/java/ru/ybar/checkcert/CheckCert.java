package ru.ybar.checkcert;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;

public class CheckCert {

    private static Logger logger = Logger.getLogger(CheckCert.class.getName());

    private static String dateFormat = "dd-MM-yyyy HH:mm:ss";

    public CheckCert() {
        createTable();
    }

    /**
     * Read the file and returns the byte array
     *
     * @param file
     * @return the bytes of the file
     */
    private byte[] readFile(String file) {
        ByteArrayOutputStream bos = null;
        File f = new File(file);
        try (FileInputStream fis = new FileInputStream(f);) {

            byte[] buffer = new byte[1024];
            bos = new ByteArrayOutputStream();
            for (int len; (len = fis.read(buffer)) != -1;) {
                bos.write(buffer, 0, len);
            }
        } catch (FileNotFoundException e) {
            logger.log(Level.SEVERE, "File cert not found: {0}", e.getMessage());
        } catch (IOException e2) {
            logger.log(Level.SEVERE, "Error read file: {0}", e2.getMessage());
        }
        return bos != null ? bos.toByteArray() : null;
    }

    /**
     * Connect to the test.db database
     *
     * @return the Connection object
     */
    private Connection connect() {
        // SQLite connection string
        String url = "jdbc:sqlite:cert.db";

        try {
            Class.forName("org.sqlite.JDBC");
            return DriverManager.getConnection(url);
        } catch (SQLException | ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Connect: {0}", e.getMessage());
            System.exit(1);
            return null;
        }
    }

    /**
     * Create a table if it doesn't exist
     */
    private void createTable() {
        String sql = "CREATE TABLE IF NOT EXISTS cert (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT(255) NOT NULL, cert BLOB, namekey TEXT(255), key BLOB, filename TEXT(255), valid TEXT);";

        try (Connection conn = connect(); Statement statement = conn.createStatement();) {
            statement.execute(sql);
            logger.log(Level.INFO, "Create DB Ok");
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error create DB {0}", e.getMessage());
        }
    }

    /**
     * Obtaining the last day of life of the certificate
     *
     * @param pathtoCertificate
     * @return
     */
    private String getValidDateCert(String pathtoCertificate) {

        Date valid;
        try (FileInputStream fr = new FileInputStream(pathtoCertificate);) {

            CertificateFactory cf = CertificateFactory.getInstance("X509");

            X509Certificate c;
            c = (X509Certificate) cf.generateCertificate(fr);
            logger.log(Level.INFO, "++++Certificate Verification++++++++");

            valid = c.getNotAfter();
            return new SimpleDateFormat(dateFormat).format(valid);

        } catch (CertificateException | IOException e) {
            logger.log(Level.SEVERE, "Certificate is Invalid");
        }
        return null;
    }

    /**
     * Days of certificate life remaining
     *
     * @param pathtoCertificate
     * @return
     */
    private String getDaysLeft(String validDate) {
        Date today = new Date();
        try {
            Date date = new SimpleDateFormat(dateFormat).parse(validDate);
            return Long.toString((date.getTime() - today.getTime()) / (24 * 60 * 60 * 1000));
        } catch (ParseException e) {
            logger.log(Level.SEVERE, "Error Date format: {0}", getValidDateCert(validDate));
        }
        return "-999";
    }

    public void delCert(int id) {
        String delSQL = "Delete from cert where id=?";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(delSQL)) {
            pstmt.setInt(1, id);
            pstmt.execute();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error delete:{0}", e.getMessage());
        } finally {
            logger.log(Level.SEVERE, "End delete");
        }
    }

    /**
     * Upload cert for a specific material
     *
     * @param filename
     * @param name
     */
    public void uploadCert(String filename, String name) {

        int numRowsInserted = 0;
        String insertSQL = "INSERT INTO cert " + "(\"cert\",\"name\",\"filename\",\"valid\") values" + "(?,?,?,?)";

        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

            // set parameters
            pstmt.setBytes(1, readFile(filename));
            pstmt.setString(2, name);
            pstmt.setString(3, new File(filename).getName());
            pstmt.setString(4, getValidDateCert(filename));
            numRowsInserted = pstmt.executeUpdate();
            logger.log(Level.INFO, "Stored the file in the BLOB column = {0}", numRowsInserted);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error upload:{0}", e.getMessage());
        } finally {
            logger.log(Level.SEVERE, "End upload");
        }
    }

    public void uploadKey(String filename, int id) {
        // update sql
        String insertSQL = "UPDATE cert SET \"key\" = ?,\"namekey\" = ? where \"id\" = ?;";

        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

            // set parameters
            pstmt.setBytes(1, readFile(filename));
            pstmt.setString(2, new File(filename).getName());
            pstmt.setInt(3, id);

            pstmt.executeUpdate();
            logger.log(Level.SEVERE, "Stored the file in the BLOB column.");

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error upload:{0}", e.getMessage());
        } finally {
            logger.log(Level.SEVERE, "End upload");
        }
    }

    /**
     * read the picture file and insert into the material master table
     *
     * @param certId
     */
    public void saveCert(int certId, File path) {
        // update sql
        String selectSQL = "SELECT cert, filename, key, namekey FROM cert WHERE id=?";

        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(selectSQL);) {

            pstmt.setInt(1, certId);
            try (ResultSet rs = pstmt.executeQuery();) {
                // write binary stream into file
                File file = new File(path, rs.getString("filename"));
                try (FileOutputStream fos = new FileOutputStream(file);) {
                    logger.log(Level.INFO, "Read BLOB to file {0}", file.getAbsolutePath());

                    InputStream input = rs.getBinaryStream("cert");
                    byte[] buffer = new byte[1024];
                    while (input.read(buffer) > 0) {
                        fos.write(buffer);
                    }

                }
                String nameKey = rs.getString("namekey").trim();
                if (!nameKey.equals("")) {
                    file = new File(path, nameKey);
                    try (FileOutputStream fos = new FileOutputStream(file);) {
                        logger.log(Level.INFO, "Read BLOB to file {0}", file.getAbsolutePath());

                        InputStream input = rs.getBinaryStream("key");
                        byte[] buffer = new byte[1024];
                        while (input.read(buffer) > 0) {
                            fos.write(buffer);
                        }
                    }
                }
            }
        } catch (SQLException | IOException e) {
            logger.log(Level.SEVERE, "Error Donwnload cert from db {}", e.getMessage());
        }

    }

    /**
     * Returns a list of certificate names
     *
     * @return
     */
    public String[] listCert() {
        String selectSQL = "SELECT name, COUNT(*) over () cn from cert;";

        String[] listName = null;

        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(selectSQL);
                ResultSet rs = pstmt.executeQuery();) {

            int n = 0;
            while (rs.next()) {
                if (n == 0) {
                    listName = new String[rs.getInt("cn")];
                }
                listName[n] = rs.getString("name");
                n++;
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error list cert from db {}", e.getMessage());
        }
        return listName;
    }

    public DefaultTableModel listCertTable() {
        DefaultTableModel model = new DefaultTableModel(
                new String[]{"id", "Desc", "File Cert", "File key", "Date Valid", "Days left"}, 0);
        String selectSQL = "SELECT id, name, filename, namekey, valid from cert order by valid asc;";
        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(selectSQL);
                ResultSet rs = pstmt.executeQuery();) {

            while (rs.next()) {
                int id = rs.getInt("id");
                String name = rs.getString("name");
                String filename = rs.getString("filename");
                String namekey = rs.getString("namekey");
                String valid = rs.getString("valid");
                String validDay = getDaysLeft(rs.getString("valid"));
                model.addRow(new Object[]{id, name, filename, namekey, valid, validDay});
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error read cert from db {}", e.getMessage());
        }
        return model;
    }
}
