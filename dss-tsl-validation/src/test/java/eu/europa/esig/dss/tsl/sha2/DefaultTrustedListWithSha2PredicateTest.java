package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultTrustedListWithSha2PredicateTest {

    private DSSDocument tl;

    private DSSDocument wrongTl;

    private DSSDocument sha2Document;

    private DSSDocument wrongSha2Document;

    @BeforeEach
    public void init() {
        tl = new FileDocument("src/test/resources/sk-tl.xml");
        sha2Document = new InMemoryDocument("8c43cc710e6d1cc77189c6ca4ef3932e98860575aaaaab77446f167c4fb11618".getBytes());

        wrongTl = new FileDocument("src/test/resources/sk-tl-sn-95.xml");
        wrongSha2Document = new InMemoryDocument("c662c9f5252fa9bca9d98d038f3ae2d139f1406c63e2d8b709ba857e140229c1".getBytes());
    }

    @Test
    public void test() {
        DefaultTrustedListWithSha2Predicate currentTimePredicate = new MockDefaultTrustedListWithSha2Predicate(new Date());

        Exception exception = assertThrows(NullPointerException.class, () -> currentTimePredicate.test(null));
        assertEquals("Document shall be provided!", exception.getMessage());

        DocumentWithSha2 documentWithSha2 = new DocumentWithSha2(null, null);
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().contains("No cached document has been found."));

        documentWithSha2 = new DocumentWithSha2(tl, null);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().contains("No sha2 document has been found."));

        documentWithSha2 = new DocumentWithSha2(null, sha2Document);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().contains("No cached document has been found."));

        documentWithSha2 = new DocumentWithSha2(tl, wrongSha2Document);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("Digest present within sha2 file") && s.contains(" do not match digest of")));

        documentWithSha2 = new DocumentWithSha2(tl, sha2Document);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().contains("NextUpdate '2020-02-19T00:00:00Z' has been reached."));

        Calendar calendar = Calendar.getInstance();
        calendar.set(2020, Calendar.JANUARY , 1);
        DefaultTrustedListWithSha2Predicate pastTimePredicate = new MockDefaultTrustedListWithSha2Predicate(calendar.getTime());

        documentWithSha2 = new DocumentWithSha2(tl, wrongSha2Document);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("Digest present within sha2 file") && s.contains(" do not match digest of")));

        documentWithSha2 = new DocumentWithSha2(wrongTl, sha2Document);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("Digest present within sha2 file") && s.contains(" do not match digest of")));

        documentWithSha2 = new DocumentWithSha2(tl, wrongTl);

        assertFalse(currentTimePredicate.test(documentWithSha2));
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("Digest present within sha2 file") && s.contains(" do not match digest of")));

        documentWithSha2 = new DocumentWithSha2(tl, sha2Document);

        assertTrue(pastTimePredicate.test(documentWithSha2));
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        pastTimePredicate.setCacheExpirationTime(0);

        assertFalse(pastTimePredicate.test(documentWithSha2));
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
    }

    private static class MockDefaultTrustedListWithSha2Predicate extends DefaultTrustedListWithSha2Predicate {

        private final Date validationTime;

        public MockDefaultTrustedListWithSha2Predicate(Date validationTime) {
            this.validationTime = validationTime;
        }

        @Override
        protected Date getCurrentTime() {
            return validationTime;
        }

    }

}
