package com.example.merkletree;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
public class MerkleTreesApplication {

    public static void main(String[] args) {
        SpringApplication.run(MerkleTreesApplication.class, args);
    }

    public static final String PROVIDER_NAME = "BC";

    @PostConstruct
    public void setup() {
        setupCrypto();
        test();
    }

    public void setupCrypto() {

        Security.addProvider(new BouncyCastleProvider());

        if (Security.getProvider(PROVIDER_NAME) == null) {
            log.error("Bouncy Castle provider is not installed");
        } else {
            log.info("Bouncy Castle provider is installed.");
        }

        Security.setProperty("crypto.policy", "unlimited");
    }

    public void test() {
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

        ArchiveTimeStamp archiveTimeStamp = createArchiveTimestamp(rootHash, reducedTree, hashAlgorithm);
        System.out.println("Generated archive timestamp: " + debugArchiveTimeStamp(archiveTimeStamp));
    }

    private String debugArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp) {
        return "ArchiveTimeStamp{" +
                "digestAlgorithm=" + archiveTimeStamp.getDigestAlgorithm() +
                ", reducedHashTree=" + Arrays.toString(archiveTimeStamp.getReducedHashTree()) +
                ", getHashTreeLeaf()=" + Arrays.toString(archiveTimeStamp.getHashTreeLeaf().getValues()) +
                ", getTimeStamp().getContent()=" + archiveTimeStamp.getTimeStamp().getContent() +
                '}';
    }

    /**
     * Create an archive timestamp according to RFC 4998.
     *
     * @param rootHash        The root hash of the Merkle tree.
     * @param reducedHashTree The reduced hash tree containing the path to some node that shall be archived.
     * @param hashAlgorithm   The hash algorithm used to create the hash tree.
     * @return The created archive timestamp.
     */
    public ArchiveTimeStamp createArchiveTimestamp(byte[] rootHash, PartialHashtree[] reducedHashTree,
            HashAlgorithm hashAlgorithm) {

        // Obtain a timestamp for the root hash value
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        TimeStampRequest request = generator.generate(hashAlgorithm.getTspOid(), rootHash);
        ContentInfo timeStamp = requestTimeStamp(request).toCMSSignedData().toASN1Structure();

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(hashAlgorithm.getTspOid());

        // Create the archive timestamp
        ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(identifier, reducedHashTree, timeStamp);
        return archiveTimeStamp;
    }

    /**
     * Taken from
     * https://www.javatips.net/api/jsign-master/jsign-core/src/main/java/net/jsign/timestamp/RFC3161Timestamper.java
     *
     * @param request
     * @return
     * @throws IOException
     */
    private TimeStampToken requestTimeStamp(TimeStampRequest request) {
        URL tsaurl;
        try {
            tsaurl = URI.create("https://zeitstempel.dfn.de/").toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("Invalid URL", e);
        }

        HttpURLConnection conn;
        try {
            byte encodedRequest[] = request.getEncoded();

            conn = (HttpURLConnection) tsaurl.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-type", "application/timestamp-query");
            conn.setRequestProperty("Content-length", String.valueOf(encodedRequest.length));
            conn.setRequestProperty("Accept", "application/timestamp-reply");
            conn.setRequestProperty("User-Agent", "Transport");

            conn.getOutputStream().write(encodedRequest);
            conn.getOutputStream().flush();

            if (conn.getResponseCode() >= 400) {
                throw new RuntimeException(
                        "Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode()
                                + " - " + conn.getResponseMessage());
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not open a http connection for timestamping due: " + e.getMessage());
        }

        try (ASN1InputStream inputStream = new ASN1InputStream(conn.getInputStream())) {

            TimeStampResp resp = TimeStampResp.getInstance(inputStream.readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(request);
            if (response.getStatus() != 0) {
                throw new IOException("Unable to complete the timestamping due to an invalid response ("
                        + response.getStatusString() + ")");
            }

            return response.getTimeStampToken();

        } catch (Exception e) {
            throw new RuntimeException("Unable to complete the timestamping", e);
        }
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
