package com.example.merkletree;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MerkleTreeNode {
    private byte[] hash;
    private TestComposite composite;
    private List<MerkleTreeNode> children = new ArrayList<>();
    private final HashAlgorithm hashAlgorithm;

    public MerkleTreeNode(TestComposite testComposite, HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.composite = testComposite;
        for (TestComposite compChild : testComposite.getChildren()) {
            children.add(new MerkleTreeNode(compChild, hashAlgorithm));
        }
        byte[][] childHashes = children.stream().map(MerkleTreeNode::getHash).toArray(byte[][]::new);
        calculateHash(childHashes);
    }

    public byte[] getHash() {
        return hash;
    }

    public List<MerkleTreeNode> getChildren() {
        return children;
    }

    /**
     * Calculate hash of {@link MerkleTreeNode#composite} content and add together with {@code childrenHashes}. Sort and
     * concatenate {@code allHashes} and calculate the own hash from the result.
     *
     * @param childrenHashes The hashes of all child merkle tree nodes.
     */
    private void calculateHash(byte[][] childrenHashes) {

        byte[] compositeContentHash = CryptoUtils.hash(composite.getContent().getBytes(), hashAlgorithm);

        byte[][] allHashes = new byte[childrenHashes.length + 1][];
        System.arraycopy(childrenHashes, 0, allHashes, 0, childrenHashes.length);
        allHashes[childrenHashes.length] = compositeContentHash;

        Arrays.sort(allHashes);
        String concatenatedHashes = Arrays.stream(allHashes).map(Arrays::toString).collect(Collectors.joining());

        hash = CryptoUtils.hash(concatenatedHashes.getBytes(), hashAlgorithm);
    }
}
