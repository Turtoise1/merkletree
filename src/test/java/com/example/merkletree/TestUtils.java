package com.example.merkletree;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Date;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

public class TestUtils {
    public static void assertNear(Date expected, Date actual, long marginMs) {
        long diff = Math.abs(expected.getTime() - actual.getTime());
        if (diff > marginMs) {
            throw new AssertionError(
                    "Expected date: " + expected + " but was " + actual + " (difference: " + diff + " ms)");
        }
    }

    public static X509CertificateHolder loadCertificateFromPEM(String path) throws IOException {
        // PEM-Format: Verwende PEMParser
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(path)))) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return (X509CertificateHolder) object;
            } else if (object instanceof Certificate) {
                return new X509CertificateHolder(((Certificate) object).getEncoded());
            } else {
                throw new IllegalArgumentException("Ungültiges PEM-Format: " + object.getClass());
            }
        }
    }
}
