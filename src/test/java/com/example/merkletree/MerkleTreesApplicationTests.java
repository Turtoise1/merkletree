package com.example.merkletree;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MerkleTreesApplicationTests {

    @Test
    public void callCreateArchiveTimeStamp() throws IOException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        TestComposite randomAncestor = pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode ancestorNode = tree.findAncestor(randomAncestor);
        byte[] rootHash = tree.getHash();
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(ancestorNode.getHash());

        ArchiveTimeStamp result = TimeStamping.createArchiveTimeStamp(rootHash, reducedTree, hashAlgorithm);

        String algorithmResult = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        String algorithmIdentifierResult = result.getDigestAlgorithmIdentifier().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmIdentifierResult);

        PartialHashtree resultLeaf = result.getHashTreeLeaf();
        PartialHashtree expectedLeaf = ancestorNode.getPathFromAncestor(ancestorNode.getHash())[0];
        assertEquals(expectedLeaf.toString(), resultLeaf.toString());
    }

    @Test
    public void callRequestTimeStamp() throws IOException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), tree.getHash());

        TimeStampToken result = TimeStamping.requestTimeStamp(request);

        Date time = result.getTimeStampInfo().getGenTime();
        TestUtils.assertNear(new Date(), time, 1000);

        String issuerResult = result.getSID().getIssuer().toString();
        assertEquals(
                "C=DE,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,OU=DFN-PKI,CN=DFN-Verein Global Issuing CA",
                issuerResult);

        String algorithmResult = result.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

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
