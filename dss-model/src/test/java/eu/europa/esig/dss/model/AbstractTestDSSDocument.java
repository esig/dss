package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestDSSDocument {

    @Test
    public void persistenceTest() {
        // See {@link <a href="https://ec.europa.eu/digital-building-blocks/tracker/browse/DSS-3595">DSS-3595</a>}
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertEquals(document, getPersistenceTestDocument());
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertNotEquals(document, altDocument);
            assertFalse(hashSet.contains(altDocument));
        }
    }

    protected abstract DSSDocument getPersistenceTestDocument();

    protected abstract List<DSSDocument> getPersistenceTestAlternativeDocuments();

}
