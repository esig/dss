package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CMSSignedContentDocumentTest {

    private DSSDocument cmsDocument;

    @BeforeEach
    public void init() {
        cmsDocument = new InMemoryDocument(
                CMSSignedContentDocumentTest.class.getResourceAsStream("/validation/CAdESDoubleLTA.p7m"));
    }

    @Test
    public void persistenceTest() {
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertFalse(hashSet.contains(altDocument));
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new CMSSignedContentDocument(cmsDocument, CMSObjectIdentifiers.data);
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        return Arrays.asList(
                new CMSSignedContentDocument(cmsDocument),
                new CMSSignedContentDocument(cmsDocument, CMSObjectIdentifiers.signedData),
                new CMSSignedContentDocument(new InMemoryDocument("Alt data".getBytes()), CMSObjectIdentifiers.data)
        );
    }

}
