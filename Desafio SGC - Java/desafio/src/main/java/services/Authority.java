package services;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

public class Authority {
	
	private static EntityManagerFactory entityManagerFactory = Persistence.createEntityManagerFactory("BancoPU");
	
	private static EntityManager entityManager = entityManagerFactory.createEntityManager();
	

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
        Keys chaves = new Keys(); // instancia a classe keys
        
        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong())); //armazena o serialnumber que é um grande inteiro

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=root-cert"); //o x500name é uma classe entidade que tem suporte aos atributos do x500
        X500Name rootCertSubject = rootCertIssuer; // aqui define que é um AC auto assinado, pois diz que o issuer (emissor) é o mesmo que o subject (quem quer o certificado)
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(chaves.privateKey); //criando a assinatura 
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, chaves.publicKey);// cria o certificado com as caracteristicas

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils(); // Crie uma classe de utilitário pré-configurada com uma calculadora de resumo SHA-1 com base na implementação padrão
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); //marca a extensão com critica
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(chaves.publicKey));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner); //recebe o criador de certificado com as caracteristicas e chama a variavel que é responsavel para assinar
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder); // recebe o certificado

        writeCertToFileBase64Encoded(rootCert, "root-cert.cer");
        
        //Até aqui é tudo direcionado a AC raiz autoassinado
        
        exportKeyPairToKeystoreFile(chaves.privateKey, rootCert, "root-cert", "root-cert.pfx", "PKCS12", "pass");

        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        //------------------------------------------------------
          X500Name issuedCertSubject = new X500Name("CN=issued-cert");
          BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
          

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, chaves.publicKey2);
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
//
//        // Sign the new KeyPair with the root cert Private Key
         ContentSigner csrContentSigner = csrBuilder.build(chaves.privateKey);
         PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
//
//        // Use the Signed KeyPair and CSR to generate an issued Certificate
//        // Here serial number is randomly generated. In general, CAs use
//        // a sequence to generate Serial number and avoid collisions
          X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());
//
        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils(); //Crie uma classe de utilitário pré-configurada com uma calculadora de resumo SHA-1 com base na implementação padrão
//
//
//        // Add Issuer cert identifier as Extension
          issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
          issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
//
//        // Add intended key usage extension if needed
//        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
//
//        // Add DNS name is cert is to used for SSL
//        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
//                new GeneralName(GeneralName.dNSName, "mydomain.local"),
//                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
//        }));
//
         X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
         X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);
//
//        // Verify the issued cert signature against the root (issuer) cert
         issuedCert.verify(chaves.publicKey, BC_PROVIDER);
//
        writeCertToFileBase64Encoded(issuedCert, "issued-cert.cer");
        exportKeyPairToKeystoreFile(chaves.privateKey2, issuedCert, "issued-cert", "issued-cert.pfx", "PKCS12", "pass");
        
     // INSERT
     		Certificates certificados = new Certificates(); // alt + shift + r  (renomeia)
     		
     		certificados.setSerialNumber(rootSerialNum);
     		
     		entityManager.getTransaction().begin();
     		entityManager.persist(certificados);
     		entityManager.getTransaction().commit();
     		
     		certificados.setEmissor(rootCertIssuer.toString());
     		
     		entityManager.getTransaction().begin();
     		entityManager.persist(certificados);
     		entityManager.getTransaction().commit();
     		
     		certificados.setReceptor(rootCertSubject.toString());
     		
     		entityManager.getTransaction().begin();
     		entityManager.persist(certificados);
     		entityManager.getTransaction().commit();
        

    }

    static void exportKeyPairToKeystoreFile(PrivateKey privateKey, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, privateKey,null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }
}