package com.example.merkletree.dss;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
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

            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            // Add the signing certificate explicitly as trusted (for self-signed certs)
            trustedCertificateSource.addCertificate(privateKey.getCertificate());
            // Add the TSA certificate
            addTsaCertificates(trustedCertificateSource);

            DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

            // Create a list of documents to sign
            List<DSSDocument> documentsToSign = new ArrayList<>();
            documentsToSign.add(new FileDocument("src/test/resources/collection/metadata.example.json"));
            documentsToSign.add(new FileDocument("src/test/resources/collection/permission.example.json"));
            documentsToSign.add(new FileDocument("src/test/resources/collection/structure.example.json"));

            // Preparing parameters for the ASiC-E signature
            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();

            // We choose the level of the signature (-B, -T, -LT or -LTA).
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            // We choose the container type (ASiC-S pr ASiC-E)
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

            // We set the digest algorithm to use with the signature algorithm. You must use
            // the same parameter when you invoke the method sign on the token. The default
            // value is SHA256
            parameters.setDigestAlgorithm(digestAlgorithm);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            // Create ASiC service for signature
            ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(documentsToSign, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the xadesService to sign the document with the signature value
            // obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(documentsToSign, parameters, signatureValue);

            // Initialize a SignedDocumentExtender, which will load the relevant
            // implementation of a DocumentExtender based on document's format
            SignedDocumentExtender documentExtender = SignedDocumentExtender.fromDocument(signedDocument);

            // init TSP source for timestamp requesting
            TSPSource tspSource = getOnlineTSPSource();

            // configure commonCertificateVerifier if needed
            // Set the CertificateVerifier instantiated earlier
            documentExtender.setCertificateVerifier(certificateVerifier);

            // Set the TSPSource for a timestamp extraction
            documentExtender.setTspSource(tspSource);

            // Extend the document, by specifying the target augmentation profile
            signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_T);

            // init revocation sources for CRL/OCSP requesting
            certificateVerifier.setCrlSource(new OnlineCRLSource());
            certificateVerifier.setOcspSource(new OnlineOCSPSource());

            // Trust anchors should be defined for revocation data requesting
            certificateVerifier.setTrustedCertSources(trustedCertificateSource);

            // Extend the document
            signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_LT);

            // Extend the document
            signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_LTA);

            // Save the signed container
            signedDocument.save("target/signed_container.asice");

            System.out.println("ASiC container with XAdES signatures created successfully!");
            System.out.println("Saved to: target/signed_container.asice");

            signingToken.close();
        } catch (Exception e) {
            System.err.println("Error creating ASiC container: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static TSPSource getOnlineTSPSource() {
        final String tspServer = "https://zeitstempel.dfn.de/";
        return new OnlineTSPSource(tspServer);
    }

    private static void addTsaCertificates(TrustedCertificateSource source) {
        String certDirectory = "src/test/resources/certificates/";
        String dfnPkiDirectory = certDirectory + "dfn-pki-global-bundle/";
        CertificateToken timestampCert = DSSUtils
                .loadCertificate(new File(certDirectory + "PN_Zeitstempel_2023.cer"));
        source.addCertificate(timestampCert);
        CertificateToken issuingCert = DSSUtils
                .loadCertificate(new File(dfnPkiDirectory + "DFN-Verein_Global_Issuing_CA.cer"));
        source.addCertificate(issuingCert);
        CertificateToken intermediateCert = DSSUtils
                .loadCertificate(new File(dfnPkiDirectory + "DFN-Verein_Certification_Authority_2.cer"));
        source.addCertificate(intermediateCert);
        // root cert T-TeleSec GlobalRoot Class 2 should be preinstalled
    }
}
