package com.example.merkletree;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TSPAlgorithms;

public enum HashAlgorithm {
    SHA256("SHA-256", TSPAlgorithms.SHA256, NISTObjectIdentifiers.id_sha256);

    private String algorithmName;
    private ASN1ObjectIdentifier tspOid;
    private ASN1ObjectIdentifier nistOid;

    HashAlgorithm(String algorithmName, ASN1ObjectIdentifier tspOid, ASN1ObjectIdentifier nistOid) {
        this.algorithmName = algorithmName;
        this.tspOid = tspOid;
        this.nistOid = nistOid;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public ASN1ObjectIdentifier getTspOid() {
        return tspOid;
    }

    public ASN1ObjectIdentifier getNistOid() {
        return nistOid;
    }

    public MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return algorithmName;
    }
}
