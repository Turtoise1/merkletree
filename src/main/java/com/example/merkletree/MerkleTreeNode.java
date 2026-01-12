package com.example.merkletree;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.tsp.PartialHashtree;

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
        calculateHash();
    }

    public byte[] getHash() {
        return hash;
    }

    public List<MerkleTreeNode> getChildren() {
        return children;
    }

    /**
     * Search the ancestors of this node for some node where {@link MerkleTreeNode#hash} matches the given hash. Returns
     * all nodes and their children that lie on the path as partial hashtrees.
     *
     * @param ancestorHash The hash to search for.
     * @return The list of partial hashtrees on the path to the ancestor node, or {@code null} if not found.
     */
    public PartialHashtree[] getPathToAncestor(byte[] ancestorHash) {
        PartialHashtree[] path = null;

        // recursion anchor
        if (Arrays.equals(hash, ancestorHash)) {
            path = new PartialHashtree[1];
            path[0] = new PartialHashtree(getContentHashesSorted());
            return path;
        }

        // recursion step
        for (int i = 0; i < children.size(); i++) {
            MerkleTreeNode child = children.get(i);
            PartialHashtree[] childPath = child.getPathToAncestor(ancestorHash);
            if (childPath != null) {
                path = new PartialHashtree[childPath.length + 1];
                path[0] = new PartialHashtree(getContentHashesSorted());
                System.arraycopy(childPath, 0, path, 1, childPath.length);
                return path;
            }
        }

        // has no ancestor with the given hash
        return null;
    }

    /**
     * Try to find an ancestor node that was built on the given composite.
     *
     * @param composite The composite to search in this tree.
     * @return The ancestor node or {@code null} if not found.
     */
    public MerkleTreeNode findAncestor(TestComposite composite) {
        if (composite.equals(this.composite)) {
            return this;
        }

        for (MerkleTreeNode child : children) {
            MerkleTreeNode ancestor = child.findAncestor(composite);
            if (ancestor != null) {
                return ancestor;
            }
        }

        return null;
    }

    /**
     * Gets the hash of the corresponding test composite content as well as the hashes of all child merkle tree nodes.
     */
    private byte[][] getContentHashesSorted() {
        byte[][] hashes = new byte[children.size() + 1][];
        for (int i = 0; i < children.size(); i++) {
            hashes[i] = children.get(i).getHash();
        }
        hashes[children.size()] = CryptoUtils.hash(composite.getContent().getBytes(), hashAlgorithm);
        Arrays.sort(hashes, new Comparator<byte[]>() {
            @Override
            public int compare(byte[] a, byte[] b) {
                for (int i = 0; i < Math.min(a.length, b.length); i++) {
                    if (a[i] != b[i]) {
                        return Byte.compare(a[i], b[i]);
                    }
                }
                return Integer.compare(a.length, b.length);
            }
        });
        return hashes;
    }

    /**
     * Calculate hash of {@link MerkleTreeNode#composite} content and add together with the hashes of all child nodes.
     * Sort and concatenate all these hashes and calculate the own hash from the result.
     *
     * @param childrenHashes The hashes of all child merkle tree nodes.
     */
    private void calculateHash() {
        byte[][] allHashes = getContentHashesSorted();

        String concatenatedHashes = Arrays.stream(allHashes).map(Arrays::toString).collect(Collectors.joining());

        hash = CryptoUtils.hash(concatenatedHashes.getBytes(), hashAlgorithm);
    }
}
