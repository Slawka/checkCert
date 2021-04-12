package ru.ybar.checkcert;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;
import org.apache.http.util.TextUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public class CheckCert {

    private static Logger logger = Logger.getLogger(CheckCert.class.getName());

    private static String dateFormat = "dd-MM-yyyy HH:mm:ss";
    private String endOfDay = "";

    private void setEndOfDay(String endOfDay) {
        if (this.endOfDay.equals("")) {
            this.endOfDay = "Expires ID = ";
        }
        this.endOfDay = endOfDay;
    }

    public String getEndOfDay() {
        return endOfDay;
    }

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
        try ( FileInputStream fis = new FileInputStream(f);) {

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
    public Connection connect() {
        // SQLite connection string
        String url = "jdbc:h2:./cert;CIPHER=AES";
        String user = "sa";
        String pwds = "test" + " userpwd";
        try {
            Class.forName("org.h2.Driver");
            return DriverManager.getConnection(url, user, pwds);
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
        String sql = "CREATE TABLE IF NOT EXISTS PUBLIC.CERT (\n"
                + "	ID BIGINT NOT NULL AUTO_INCREMENT,\n"
                + "	NAME VARCHAR(255),\n"
                + "	CERT BLOB,\n"
                + "	NAMECERT VARCHAR(255),\n"
                + "	\"KEY\" BLOB,\n"
                + "	NAMEKEY VARCHAR(255),\n"
                + "	CSR BLOB,\n"
                + "	NAMECSR VARCHAR(255),\n"
                + "	VALID DATE\n"
                + ");";

        try ( Connection conn = connect();  Statement statement = conn.createStatement();) {
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
        try ( FileInputStream fr = new FileInputStream(pathtoCertificate);) {

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
        String delSQL = "Delete FROM PUBLIC.CERT where ID=?";
        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(delSQL)) {
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
        String insertSQL = "INSERT INTO PUBLIC.CERT " + "(\"CERT\",\"NAME\",\"NAMECERT\",\"VALID\") values" + "(?,?,?,?)";

        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

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
        String insertSQL = "UPDATE PUBLIC.CERT SET \"KEY\" = ?,\"NAMEKEY\" = ? where \"ID\" = ?;";

        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

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
    public void saveCert(int certId, String type, File path) {
        // update sql
        String selectSQL = "SELECT \"" + type + "\", \"NAME" + type + "\" FROM PUBLIC.CERT WHERE ID=?;";

        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(selectSQL);) {

            pstmt.setInt(1, certId);
            try ( ResultSet rs = pstmt.executeQuery();) {
                // write binary stream into file
                System.out.println("NAME" + type);
                rs.next();
                System.out.println(rs.getString("NAME" + type));
                File file = new File(path, rs.getString("NAME" + type).replaceAll("[, ]","_"));
                try ( FileOutputStream fos = new FileOutputStream(file);) {
                    logger.log(Level.INFO, "Read BLOB to file {0}", file.getAbsolutePath());

                    InputStream input = rs.getBinaryStream(type);
                    byte[] buffer = new byte[1024];
                    while (input.read(buffer) > 0) {
                        fos.write(buffer);
                    }

                }
            }
        } catch (SQLException | IOException e) {
            e.printStackTrace();
            logger.log(Level.SEVERE, "Error Donwnload " + type + " from db " + selectSQL, e.getMessage());
        }

    }

    /**
     * Returns a list of certificate names
     *
     * @return
     */
    public String[] listCert() {
        String selectSQL = "SELECT NAME, COUNT(*) over () cn FROM PUBLIC.CERT;";

        String[] listName = null;

        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(selectSQL);  ResultSet rs = pstmt.executeQuery();) {

            int n = 0;
            while (rs.next()) {
                if (n == 0) {
                    listName = new String[rs.getInt("cn")];
                }
                listName[n] = rs.getString("NAME");
                n++;
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error list cert from db {}", e.getMessage());
        }
        return listName;
    }

    public DefaultTableModel listCertTable() {
        DefaultTableModel model = new DefaultTableModel(
                new String[]{"id", "Desc", "File Cert", "File key", "CSR", "Date Valid", "Days left"}, 0);
        String selectSQL = "SELECT ID, NAME, NAMECERT, NAMEKEY, NAMECSR, VALID FROM PUBLIC.CERT order by valid asc;";
        try ( Connection conn = connect();  PreparedStatement pstmt = conn.prepareStatement(selectSQL);  ResultSet rs = pstmt.executeQuery();) {
            while (rs.next()) {
                int id = rs.getInt("ID");
                String name = rs.getString("NAME");
                String namecer = rs.getString("NAMECERT");
                String namekey = rs.getString("NAMEKEY");
                String namecsr = rs.getString("NAMECSR");
                String valid = rs.getString("VALID");
                String validDay = valid;
                if (validDay != null) {
                    validDay = getDaysLeft(validDay);
                    if (Integer.parseInt(validDay) < 60) {
                        setEndOfDay(getEndOfDay() + id + " ");
                    }
                }
                model.addRow(new Object[]{id, name, namecer, namekey, namecsr, valid, validDay});
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error read cert from db {}", e.getMessage());
        }
        return model;
    }

    public byte[] createCSR(String CN, String OU, String O, String C, String DNS, String IP, String type) throws IOException, OperatorCreationException {
        KeyPairGenerator KEY_PAIR_GENERATOR = null;
        int RSA_KEY_SIZE = 2048;

        try {
            KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertificateAuthorityClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        KEY_PAIR_GENERATOR.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        X500Name name = new X500NameBuilder()
                .addRDN(BCStyle.CN, CN)
                .addRDN(BCStyle.OU, OU)
                .addRDN(BCStyle.O, O)
                .addRDN(BCStyle.C, C)
                .build();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        switch (type) {
            case "client":
                extensionsGenerator.addExtension(
                        Extension.extendedKeyUsage,
                        true,
                        new ExtendedKeyUsage(
                                new KeyPurposeId[]{
                                    KeyPurposeId.id_kp_clientAuth}
                        ));
                break;
            case "server":
                extensionsGenerator.addExtension(
                        Extension.extendedKeyUsage,
                        true,
                        new ExtendedKeyUsage(
                                new KeyPurposeId[]{
                                    KeyPurposeId.id_kp_serverAuth}
                        ));
                break;
            case "clientserver":
                extensionsGenerator.addExtension(
                        Extension.extendedKeyUsage,
                        true,
                        new ExtendedKeyUsage(
                                new KeyPurposeId[]{
                                    KeyPurposeId.id_kp_clientAuth,
                                    KeyPurposeId.id_kp_serverAuth}
                        ));
        };

        if (!IP.isEmpty() || !DNS.isEmpty()) {

            List<GeneralName> namesList = new ArrayList<>();

            String[] elements = DNS.split("\r\n|\n");
            for (String element : elements) {
                namesList.add(new GeneralName(GeneralName.dNSName, element));
            }

            elements = IP.split("\r\n|\n");
            for (String element : elements) {
                namesList.add(new GeneralName(GeneralName.iPAddress, element));
            }
            GeneralNames subAtlNames = new GeneralNames(namesList.toArray(new GeneralName[]{}));

            extensionsGenerator.addExtension(
                    Extension.subjectAlternativeName, true, subAtlNames);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(name, keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter strCsr = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(strCsr);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        strCsr.close();
        //System.out.println(strCsr);

        int numRowsInserted = 0;
        String insertSQL = "INSERT INTO PUBLIC.CERT " + "(\"CSR\",\"NAMECSR\") values" + "(?,?)";

        try ( Connection conn = new CheckCert().connect();  PreparedStatement pstmt = conn.prepareStatement(insertSQL)) {

            // set parameters
            pstmt.setBytes(1, strCsr.toString().getBytes("UTF-8"));
            pstmt.setString(2, csr.getSubject().toString());
            numRowsInserted = pstmt.executeUpdate();
            logger.log(Level.INFO, "Stored the file in the BLOB column = {0}", numRowsInserted);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error upload:{0}", e.getMessage());
        } finally {
            logger.log(Level.SEVERE, "End upload");
        }

        pemObject = new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        StringWriter str = new StringWriter();
        pemWriter = new PEMWriter(str);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        System.out.println(str);

        return new byte[0];
    }

}
