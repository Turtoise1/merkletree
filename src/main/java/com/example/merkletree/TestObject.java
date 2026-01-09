package com.example.merkletree;

/**
 * A simple test object that generates a random string of numbers.
 */
public class TestObject {
    private String content = "";

    public TestObject() {
        int length = randomInt();
        for (int i = 0; i < length; i++) {
            content += String.valueOf(randomInt());
        }
    }

    private int randomInt() {
        return (int) (Math.random() * 100);
    }

    @Override
    public String toString() {
        return content;
    }
}
