package com.example.merkletree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MerkleTreesApplicationTests {

    @Test
    void callCreateArchiveTimeStamp() throws IOException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        TestComposite randomAncestor = pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode ancestorNode = tree.findAncestor(randomAncestor);
        byte[] rootHash = tree.getHash();
        PartialHashtree[] reducedTree = tree.getPathToAncestor(ancestorNode.getHash());

        ArchiveTimeStamp result = TimeStamping.createArchiveTimeStamp(rootHash, reducedTree, hashAlgorithm);

        AlgorithmIdentifier identifierResult = result.getDigestAlgorithmIdentifier();
        assertArrayEquals(identifierResult.getAlgorithm().getEncoded(), hashAlgorithm.getNistOid().getEncoded());

        PartialHashtree resultLeaf = result.getHashTreeLeaf();
        PartialHashtree expectedLeaf = ancestorNode.getPathToAncestor(ancestorNode.getHash())[0];
        assertArrayEquals(resultLeaf.getEncoded(), expectedLeaf.getEncoded());
    }

    private TestComposite generateTestComposite() {

        List<TestComposite> leftLeftChildren = new ArrayList<>();
        leftLeftChildren.add(new TestComposite(new ArrayList<>()));
        leftLeftChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite leftLeft = new TestComposite(leftLeftChildren);

        List<TestComposite> rightChildren = new ArrayList<>();
        rightChildren.add(new TestComposite(new ArrayList<>()));
        rightChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite right = new TestComposite(rightChildren);

        List<TestComposite> leftChildren = new ArrayList<>();
        leftChildren.add(leftLeft);
        leftChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite left = new TestComposite(leftChildren);

        List<TestComposite> rootChildren = new ArrayList<>();
        rootChildren.add(left);
        rootChildren.add(right);
        rootChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite root = new TestComposite(rootChildren);

        return root;
    }

    private TestComposite pickRandomAncestor(TestComposite input) {
        List<TestComposite> ancestors = flatten(input);
        return ancestors.get(ThreadLocalRandom.current().nextInt(ancestors.size()));
    }

    private List<TestComposite> flatten(TestComposite input) {
        List<TestComposite> flattened = new ArrayList<>();
        flattened.add(input);
        for (TestComposite child : input.getChildren()) {
            flattened.addAll(flatten(child));
        }
        return flattened;
    }

}
