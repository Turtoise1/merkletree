package com.example.merkletree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MerkleTreesApplicationTests {

    @Test
    public void callCreateArchiveTimeStamp() throws IOException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        TestComposite chosenDocument = pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findAncestor(chosenDocument);
        byte[] rootHash = tree.getHash();
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(chosenNode.getHash());

        ArchiveTimeStamp result = TimeStamping.createArchiveTimeStamp(rootHash, reducedTree, hashAlgorithm);

        String algorithmResult = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        String algorithmIdentifierResult = result.getDigestAlgorithmIdentifier().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmIdentifierResult);

        PartialHashtree resultLeaf = result.getHashTreeLeaf();
        PartialHashtree expectedLeaf = chosenNode.getPathFromAncestor(chosenNode.getHash())[0];
        assertEquals(expectedLeaf.toString(), resultLeaf.toString());
    }

    /**
     * Verify that {@code chosenDocument} existed using the ArchiveTimeStamp according to the verification algorithm
     * described in RFC 4998 (https://datatracker.ietf.org/doc/html/rfc4998#section-4.3).
     */
    @Test
    public void verifyArchiveTimeStamp() throws IOException, TSPException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        TestComposite chosenDocument = pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findAncestor(chosenDocument);
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(chosenNode.getHash());

        ArchiveTimeStamp result = TimeStamping.createArchiveTimeStamp(tree.getHash(), reducedTree, hashAlgorithm);

        // 1. Calculate hash value h of the data object with hash algorithm H given in field digestAlgorithm of the
        // Archive Timestamp.
        byte[] h = CryptoUtils.hash(chosenDocument.getContent().getBytes(), hashAlgorithm);

        // 2. Search for hash value h in the first list (partialHashtree) of reducedHashtree. If not present, terminate
        // verification process with negative result.
        assertEquals(true, result.getHashTreeLeaf().containsHash(h));

        // 3. Concatenate the hash values of the actual list (partialHashtree) of hash values in binary ascending order
        // and calculate the hash value h' with algorithm H. This hash value h' MUST become a member of the next higher
        // list of hash values (from the next partialHashtree). Continue step 3 until a root hash value is calculated.
        for (int i = 0; i < result.getReducedHashTree().length - 1; i++) {
            byte[] concatenatedHashes = CryptoUtils.sortAndFlatten(result.getReducedHashTree()[i].getValues());
            byte[] hPrime = CryptoUtils.hash(concatenatedHashes, hashAlgorithm);
            assertEquals(true, result.getReducedHashTree()[i + 1].containsHash(hPrime));
        }

        // 4. Check timestamp. In case of a timestamp according to [RFC3161], the root hash value must correspond to
        // hashedMessage, and digestAlgorithm must correspond to hashAlgorithm field, both in messageImprint field of
        // timeStampToken. In case of other timestamp formats, the hash value and digestAlgorithm must also correspond
        // to their equivalent fields if they exist.
        TimeStampToken timeStampToken = new TimeStampToken(
                result.getTimeStamp());
        byte[] expectedRootHash = CryptoUtils.hash(
                CryptoUtils.sortAndFlatten(
                        result.getReducedHashTree()[result.getReducedHashTree().length - 1].getValues()),
                hashAlgorithm);
        // alternative: byte[] hashedMessage = result.getTimeStampDigestValue();
        byte[] hashedMessage = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
        assertEquals(Arrays.toString(hashedMessage), Arrays.toString(expectedRootHash));

        String messageImprintAlgOID = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().toString();
        String digestAlgOID = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(messageImprintAlgOID, digestAlgOID);
    }

    @Test
    public void callRequestTimeStamp()
            throws IOException, CertificateException, OperatorCreationException, CMSException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true); // also check certificates
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), tree.getHash());

        TimeStampToken result = TimeStamping.requestTimeStamp(request);

        Date time = result.getTimeStampInfo().getGenTime();
        TestUtils.assertNear(new Date(), time, 2000);

        String issuerResult = result.getSID().getIssuer().toString();
        assertEquals(
                "C=DE,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,OU=DFN-PKI,CN=DFN-Verein Global Issuing CA",
                issuerResult);

        String algorithmResult = result.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        byte[] messageImprintDigest = result.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(tree.getHash(), messageImprintDigest);

        CMSSignedData signedData = result.toCMSSignedData();

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();

        Store<X509CertificateHolder> certificates = signedData.getCertificates();
        assertEquals(1, signers.size());
        for (SignerInformation signer : signers) {

            // dfn includes signing certificate and parent CA certificates
            Collection<X509CertificateHolder> allCertificates = certificates.getMatches(new AllSelector<>());
            assertEquals(4, allCertificates.size());

            // get the certificate of the signer
            Collection<X509CertificateHolder> signingCertificates = certificates.getMatches(result.getSID());
            assertEquals(1, signingCertificates.size());
            X509CertificateHolder certificateHolder = signingCertificates.iterator().next();

            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certificateHolder);
            SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cert);
            boolean verificationResult = signer.verify(signerInformationVerifier);
            assertTrue(verificationResult, "Failed to verify signer information for certificate of "
                    + cert.getIssuerX500Principal().getName());

        }

    }

    @Test
    public void callRequestTimeStamp_withoutCertReq()
            throws IOException, CertificateException, OperatorCreationException, CMSException {
        // Random test values
        TestComposite testComposite = generateTestComposite();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(false); // don't check certificates
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), tree.getHash());

        TimeStampToken result = TimeStamping.requestTimeStamp(request);

        Date time = result.getTimeStampInfo().getGenTime();
        TestUtils.assertNear(new Date(), time, 2000);

        String issuerResult = result.getSID().getIssuer().toString();
        assertEquals(
                "C=DE,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,OU=DFN-PKI,CN=DFN-Verein Global Issuing CA",
                issuerResult);

        String algorithmResult = result.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        byte[] messageImprintDigest = result.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(tree.getHash(), messageImprintDigest);

        CMSSignedData signedData = result.toCMSSignedData();

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();

        assertEquals(1, signers.size());
        for (SignerInformation signer : signers) {

            // no certificates requested
            Collection<X509CertificateHolder> allCertificates = signedData.getCertificates()
                    .getMatches(new AllSelector<>());
            assertEquals(0, allCertificates.size());

            X509CertificateHolder certificateHolder = TestUtils
                    .loadCertificateFromPEM(
                            "src/test/resources/certificates/dfn-pki-global-bundle/DFN-Verein_Global_Issuing_CA.pem");

            // check correct signer
            SigningCertificateV2 signingCertificate = SigningCertificateV2.getInstance(signer.getSignedAttributes()
                    .get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47")).getAttrValues().getObjectAt(0)); // id-aa-signingCertificate

            // ESSCertID hash should be the hash of the certificate holder
            ESSCertIDv2 essCertID = essCertID = signingCertificate.getCerts()[0];

            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
            DigestCalculator digestCalculator = digestCalculatorProvider
                    .get(new AlgorithmIdentifier(hashAlgorithm.getOid()));
            digestCalculator.getOutputStream().write(certificateHolder.getEncoded());
            byte[] certHash = digestCalculator.getDigest();

            assertArrayEquals(certHash, essCertID.getCertHash(), "The cert hash does not match!");
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
