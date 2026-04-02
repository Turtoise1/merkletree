package com.example.merkletree.dss;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;

import java.io.File;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

public class Playground {
    public Playground() {
    }

    public static void main(String[] args) {
        try {

            // Load the signing token (PKCS#12 file)
            Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken(
                    "src/test/resources/test.p12",
                    new PasswordProtection("changeit".toCharArray()));
            // Get the first private key entry
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            KeyStoreCertificateSource myKeystore = new KeyStoreCertificateSource(
                    new File("src/test/resources/test.p12"),
                    "PKCS12", "changeit".toCharArray());

            CertificateToken tsaCertificate = DSSUtils
                    .loadCertificate(new File("src/test/resources/certificates/PN_Zeitstempel_2023.cer"));

            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            // Add the signing certificate explicitly as trusted (for self-signed certs)
            trustedCertificateSource.addCertificate(privateKey.getCertificate());

            // Add all certificates from the keystore as trusted
            for (CertificateToken cert : myKeystore.getCertificates()) {
                trustedCertificateSource.addCertificate(cert);
            }

            // Add the TSA certificate
            trustedCertificateSource.addCertificate(tsaCertificate);

            DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

            // Create a list of documents to sign
            List<DSSDocument> documentsToSign = new ArrayList<>();
            documentsToSign.add(new FileDocument("src/test/resources/collection/metadata.example.json"));
            documentsToSign.add(new FileDocument("src/test/resources/collection/permission.example.json"));
            documentsToSign.add(new FileDocument("src/test/resources/collection/structure.example.json"));

            // Create ASiC-XAdES signature parameters
            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
            // Set the ASiC container type (ASiC-S for simple container)
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setGenerateTBSWithoutCertificate(true);

            // Create ArchiveTimestamp parameters
            XAdESTimestampParameters archiveTimestampParameters = new XAdESTimestampParameters();
            archiveTimestampParameters.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
            archiveTimestampParameters.setDigestAlgorithm(digestAlgorithm);
            parameters.setArchiveTimestampParameters(archiveTimestampParameters);

            // Create ASiC service with a properly configured CommonCertificateVerifier
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            certificateVerifier.setTrustedCertSources(trustedCertificateSource);
            certificateVerifier.setCheckRevocationForUntrustedChains(false); // Disable revocation check for self-signed
                                                                             // certs
            ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);

            final String tspServer = "https://zeitstempel.dfn.de/";
            OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
            tspSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-typ
            service.setTspSource(tspSource);

            // Sign the documents in three steps
            ToBeSigned dataToSign = service.getDataToSign(documentsToSign, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
            DSSDocument signedContainer = service.signDocument(documentsToSign, parameters, signatureValue);

            // Save the signed container
            signedContainer.save("target/signed_container.asics");

            System.out.println("ASiC container with XAdES signatures created successfully!");
            System.out.println("Saved to: target/signed_container.asics");

            signingToken.close();
        } catch (Exception e) {
            System.err.println("Error creating ASiC container: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
