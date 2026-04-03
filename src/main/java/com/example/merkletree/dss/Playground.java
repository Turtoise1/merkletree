package com.example.merkletree.dss;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;

import java.io.File;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

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

            CertificateToken tsaCertificate = DSSUtils
                    .loadCertificate(new File("src/test/resources/certificates/PN_Zeitstempel_2023.cer"));

            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            // Add the signing certificate explicitly as trusted (for self-signed certs)
            trustedCertificateSource.addCertificate(privateKey.getCertificate());
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
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            System.out.println(parameters.getSigningCertificate());

            XAdESTimestampParameters timestampParameters = new XAdESTimestampParameters(digestAlgorithm);
            parameters.setSignatureTimestampParameters(timestampParameters);

            // Create ASiC service with a properly configured CommonCertificateVerifier
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            certificateVerifier.setTrustedCertSources(trustedCertificateSource);
            ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);

            final String tspServer = "https://zeitstempel.dfn.de/";
            OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
            service.setTspSource(tspSource);

            // Sign the documents in three steps
            ToBeSigned dataToSign = service.getDataToSign(documentsToSign, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
            DSSDocument signedContainer = service.signDocument(documentsToSign, parameters, signatureValue);

            // Save the signed container
            signedContainer.save("target/signed_container.asice");

            System.out.println("ASiC container with XAdES signatures created successfully!");
            System.out.println("Saved to: target/signed_container.asice");

            signingToken.close();
        } catch (Exception e) {
            System.err.println("Error creating ASiC container: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
