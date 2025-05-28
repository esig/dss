package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocumentWithSha2Test {

    private DSSDocument containerEntry;

    @BeforeEach
    public void init() {
        containerEntry = new InMemoryDocument("Hello world".getBytes(), "helloworld");
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
            assertFalse(hashSet.contains(altDocument), altDocument.toString());
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new DocumentWithSha2(new InMemoryDocument("Hello world".getBytes()), new InMemoryDocument("sha2".getBytes()));
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        DocumentWithSha2 docWithError = (DocumentWithSha2) getPersistenceTestDocument();
        docWithError.addErrorMessage("error");
        return Arrays.asList(
                docWithError,
                new DocumentWithSha2(new InMemoryDocument("Bye world".getBytes()), new InMemoryDocument("sha2".getBytes())),
                new DocumentWithSha2(new InMemoryDocument("Hello world".getBytes()), new InMemoryDocument("sha3".getBytes()))
        );
    }

}
