package com.example.merkletree;

public enum HashAlgorithm {
    SHA256("SHA-256");

    private String algorithmName;

    HashAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public String toString() {
        return algorithmName;
    }
}
