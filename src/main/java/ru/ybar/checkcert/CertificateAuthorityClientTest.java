/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ru.ybar.checkcert;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

public class CertificateAuthorityClientTest {

    private static Logger logger = Logger.getLogger(CheckCert.class.getName());
    
    public KeyPairGenerator KEY_PAIR_GENERATOR;
    public int RSA_KEY_SIZE = 2048;
    //@SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    public String TEST_IP_ADDR = "127.0.0.1";
    
    
    public byte[] createCSR() throws IOException, OperatorCreationException {

        try {
            KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertificateAuthorityClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        KEY_PAIR_GENERATOR.initialize(RSA_KEY_SIZE);
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        X500Name name = new X500NameBuilder()
                .addRDN(BCStyle.CN, "issuerCN")
                .addRDN(BCStyle.OU, "00OU")
                .addRDN(BCStyle.O, "Company")
                .addRDN(BCStyle.C, "RU")
                .build();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[]{
                            KeyPurposeId.id_kp_clientAuth,
                            KeyPurposeId.id_kp_serverAuth}
                ));
/*
        
        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                    new GeneralName(GeneralName.dNSName, "test.com"),
                    new GeneralName(GeneralName.iPAddress, TEST_IP_ADDR),}
        );
        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, subAtlNames);
*/
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
        System.out.println(strCsr);

        int numRowsInserted = 0;
        String insertSQL = "INSERT INTO cert " + "(\"csr\",\"namecsr\") values" + "(?,?)";

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

    private X509Certificate createCertificate() throws Exception {
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded());

        X500Name issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, "issuer")
                .build();

        X500Name subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, "subject")
                .build();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CertificateHolder certHolder = new X509v3CertificateBuilder(
                issuer,
                new BigInteger("1000"),
                Date.from(Instant.now()),
                Date.from(Instant.now().plusSeconds(100000)),
                subject,
                subjectPublicKeyInfo
        )
                .build(signer);
        return (X509Certificate) certificateFactory.
                generateCertificate(
                        new ByteArrayInputStream(certHolder.getEncoded()));
    }

}
