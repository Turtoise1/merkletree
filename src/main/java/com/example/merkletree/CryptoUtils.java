package com.example.merkletree;

import java.security.MessageDigest;

public class CryptoUtils {

    public static byte[] hash(byte[] content, HashAlgorithm algorithm) {
        MessageDigest md = algorithm.getMessageDigest();
        return md.digest(content);
    }
}
