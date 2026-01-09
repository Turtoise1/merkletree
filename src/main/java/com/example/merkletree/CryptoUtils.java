package com.example.merkletree;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CryptoUtils {

    public static byte[] hash(byte[] content, HashAlgorithm algorithm) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm.toString());
            md.update(content);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm " + algorithm + " not supported!");
        }
    }
}
