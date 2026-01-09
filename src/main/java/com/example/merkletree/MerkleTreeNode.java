package com.example.merkletree;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MerkleTreeNode {
    private byte[] hash;
    private List<MerkleTreeNode> children = new ArrayList<>();
    private final HashAlgorithm hashAlgorithm;

    public MerkleTreeNode(TestObject testObject, HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        hash = CryptoUtils.hash(testObject.toString().getBytes(), hashAlgorithm);
    }

    public MerkleTreeNode(TestComposite testComposite, HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        for (TestObject leafChild : testComposite.getLeafChildren()) {
            children.add(new MerkleTreeNode(leafChild, hashAlgorithm));
        }
        for (TestComposite compChild : testComposite.getCompositeChildren()) {
            children.add(new MerkleTreeNode(compChild, hashAlgorithm));
        }
        byte[][] childrenHashes = children.stream().map(MerkleTreeNode::getHash).toArray(byte[][]::new);
        hash = calculateHash(childrenHashes);
    }

    public byte[] getHash() {
        return hash;
    }

    public List<MerkleTreeNode> getChildren() {
        return children;
    }

    private byte[] calculateHash(byte[][] childrenHashes) {
        Arrays.sort(childrenHashes);
        String concatenatedHashes = Arrays.stream(childrenHashes).map(Arrays::toString).collect(Collectors.joining());
        return CryptoUtils.hash(concatenatedHashes.getBytes(), hashAlgorithm);
    }
}
