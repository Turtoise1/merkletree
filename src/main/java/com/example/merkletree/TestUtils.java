package com.example.merkletree;

import java.util.Date;

public class TestUtils {
    public static void assertNear(Date expected, Date actual, long marginMs) {
        long diff = Math.abs(expected.getTime() - actual.getTime());
        if (diff > marginMs) {
            throw new AssertionError(
                    "Expected date: " + expected + " but was " + actual + " (difference: " + diff + " ms)");
        }
    }
}
