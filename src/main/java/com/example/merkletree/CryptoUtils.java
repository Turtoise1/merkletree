package com.example.merkletree;

import java.security.MessageDigest;
import java.util.Arrays;

public class CryptoUtils {

    public static byte[] hash(byte[] content, HashAlgorithm algorithm) {
        MessageDigest md = algorithm.getMessageDigest();
        return md.digest(content);
    }

    public static byte[] sortAndFlatten(byte[][] arrays) {
        Arrays.sort(arrays, (a, b) -> Arrays.compare(a, b));

        // Calculate the total length of the flattened array
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        // Create the flattened array
        byte[] flattened = new byte[totalLength];
        int currentIndex = 0;

        // Concatenate all sorted inner arrays
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, flattened, currentIndex, array.length);
            currentIndex += array.length;
        }

        return flattened;
    }
}
