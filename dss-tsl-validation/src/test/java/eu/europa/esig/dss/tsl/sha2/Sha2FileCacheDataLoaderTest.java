package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.tsl.job.MockDataLoader;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Sha2FileCacheDataLoaderTest {

    private static Map<String, DSSDocument> urlMap;

    private static FileCacheDataLoader fileDataLoader;

    private static DefaultTrustedListWithSha2Predicate predicate;

    private static File cacheDirectory;

    @BeforeAll
    public static void init() {
        urlMap = new HashMap<>();

        urlMap.put("tl_ok.xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_ok.sha2",
                new InMemoryDocument("8c43cc710e6d1cc77189c6ca4ef3932e98860575aaaaab77446f167c4fb11618".getBytes()));
        urlMap.put("tl_ko.xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_ko.sha2",
                new InMemoryDocument("c662c9f5252fa9bca9d98d038f3ae2d139f1406c63e2d8b709ba857e140229c1".getBytes()));
        urlMap.put("tl_no_sha2.xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_bad.ext",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_bad.sha2",
                new InMemoryDocument("8c43cc710e6d1cc77189c6ca4ef3932e98860575aaaaab77446f167c4fb11618".getBytes()));
        urlMap.put("tl_no_dot_xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_no_dot_sha2",
                new InMemoryDocument("8c43cc710e6d1cc77189c6ca4ef3932e98860575aaaaab77446f167c4fb11618".getBytes()));

        urlMap.put("tl_refresh.xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_new.xml",
                new FileDocument("src/test/resources/sk-tl-sn-95.xml"));
        urlMap.put("tl_refresh.sha2",
                new InMemoryDocument("c662c9f5252fa9bca9d98d038f3ae2d139f1406c63e2d8b709ba857e140229c1".getBytes()));

        urlMap.put("tl_no_refresh.xml",
                new FileDocument("src/test/resources/sk-tl.xml"));
        urlMap.put("tl_no_refresh.sha2",
                new InMemoryDocument("8c43cc710e6d1cc77189c6ca4ef3932e98860575aaaaab77446f167c4fb11618".getBytes()));

        fileDataLoader = new FileCacheDataLoader();
        fileDataLoader.setCacheExpirationTime(Long.MAX_VALUE);
        fileDataLoader.setDataLoader(new MockDataLoader(urlMap));
        cacheDirectory = new File("target/cache");
        fileDataLoader.setFileCacheDirectory(cacheDirectory);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2020, Calendar.JANUARY , 1);
        predicate = new MockDefaultTrustedListWithSha2Predicate(calendar.getTime());
    }

    @AfterEach
    public void reset() throws IOException {
        Utils.cleanDirectory(cacheDirectory);
    }

    @Test
    public void goodDocTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        assertNull(sha2FileCacheDataLoader.getDocumentFromCache("tl_ok.xml"));

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_ok.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertEquals(urlMap.get("tl_ok.xml").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256));
        assertEquals(urlMap.get("tl_ok.sha2").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getSha2Document().getDigest(DigestAlgorithm.SHA256));
        assertEquals(Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA256, urlMap.get("tl_ok.xml"))), new String(DSSUtils.toByteArray(documentWithSha2.getSha2Document())));
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        assertEquals(urlMap.get("tl_ok.xml").getDigest(DigestAlgorithm.SHA256), document.getDigest(DigestAlgorithm.SHA256));

        DSSDocument documentFromCache = sha2FileCacheDataLoader.getDocumentFromCache("tl_ok.xml");
        assertEquals(documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256), documentFromCache.getDigest(DigestAlgorithm.SHA256));

        DSSDocument refreshedDocument = sha2FileCacheDataLoader.getRefreshedDocument("tl_ok.xml");
        assertEquals(urlMap.get("tl_ok.xml").getDigest(DigestAlgorithm.SHA256), refreshedDocument.getDigest(DigestAlgorithm.SHA256));

        DSSDocument sha2File = sha2FileCacheDataLoader.getSha2File("tl_ok.xml");
        assertEquals(documentWithSha2.getSha2Document().getDigest(DigestAlgorithm.SHA256), sha2File.getDigest(DigestAlgorithm.SHA256));

        assertEquals("tl_ok.sha2", sha2FileCacheDataLoader.getSha2FileUrl("tl_ok.xml"));
    }

    @Test
    public void wrongDigestDocTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_ko.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertEquals(urlMap.get("tl_ko.xml").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256));
        assertEquals(urlMap.get("tl_ko.sha2").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getSha2Document().getDigest(DigestAlgorithm.SHA256));
        assertNotEquals(Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA256, urlMap.get("tl_ko.xml"))), new String(DSSUtils.toByteArray(documentWithSha2.getSha2Document())));

        assertEquals(1, Utils.collectionSize(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().get(0).contains("do not match digest of the cached document"));
    }

    @Test
    public void noSha2DocTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_no_sha2.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertEquals(urlMap.get("tl_no_sha2.xml").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256));
        assertNull(documentWithSha2.getSha2Document());

        assertEquals(2, Utils.collectionSize(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("No sha2 document has been found")));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("Empty content is obtained!")));
    }

    @Test
    public void badExtensionDocTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_bad.ext");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertEquals(urlMap.get("tl_bad.ext").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256));
        assertNull(documentWithSha2.getSha2Document());

        assertEquals(2, Utils.collectionSize(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("No sha2 document has been found")));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("The Trusted List extension '.ext' is not supported! Shall be one of '.xml' or '.xtsl'.")));
    }

    @Test
    public void extensionNoDotDocTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_no_dot_xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertEquals(urlMap.get("tl_no_dot_xml").getDigest(DigestAlgorithm.SHA256), documentWithSha2.getDocument().getDigest(DigestAlgorithm.SHA256));
        assertNull(documentWithSha2.getSha2Document());

        assertEquals(2, Utils.collectionSize(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("No sha2 document has been found")));
        assertTrue(documentWithSha2.getErrors().stream().anyMatch(s -> s.contains("The Trusted List extension '' is not supported! Shall be one of '.xml' or '.xtsl'.")));
    }

    @Test
    public void refreshTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_refresh.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertFalse(Utils.isCollectionEmpty(documentWithSha2.getErrors()));
        assertTrue(documentWithSha2.getErrors().get(0).contains("do not match digest of the cached document"));

        urlMap.put("tl_refresh.xml", urlMap.get("tl_new.xml"));

        DSSDocument documentFromCache = sha2FileCacheDataLoader.getDocumentFromCache("tl_refresh.xml");
        assertEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), documentFromCache.getDigest(DigestAlgorithm.SHA256));

        document = sha2FileCacheDataLoader.getDocument("tl_refresh.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        documentWithSha2 = (DocumentWithSha2) document;
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        documentFromCache = sha2FileCacheDataLoader.getDocumentFromCache("tl_refresh.xml");
        assertEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), documentFromCache.getDigest(DigestAlgorithm.SHA256));

        DSSDocument refreshedDocument = sha2FileCacheDataLoader.getRefreshedDocument("tl_refresh.xml");
        assertEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), refreshedDocument.getDigest(DigestAlgorithm.SHA256));
    }

    @Test
    public void noRefreshTest() {
        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);
        sha2FileCacheDataLoader.setPredicate(predicate);

        DSSDocument document = sha2FileCacheDataLoader.getDocument("tl_no_refresh.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        DocumentWithSha2 documentWithSha2 = (DocumentWithSha2) document;
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        urlMap.put("tl_no_refresh.xml", urlMap.get("tl_new.xml"));

        DSSDocument documentFromCache = sha2FileCacheDataLoader.getDocumentFromCache("tl_no_refresh.xml");
        assertEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), documentFromCache.getDigest(DigestAlgorithm.SHA256));

        document = sha2FileCacheDataLoader.getDocument("tl_no_refresh.xml");
        assertNotNull(document);
        assertInstanceOf(DocumentWithSha2.class, document);

        documentWithSha2 = (DocumentWithSha2) document;
        assertTrue(Utils.isCollectionEmpty(documentWithSha2.getErrors()));

        documentFromCache = sha2FileCacheDataLoader.getDocumentFromCache("tl_no_refresh.xml");
        assertEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), documentFromCache.getDigest(DigestAlgorithm.SHA256));

        DSSDocument refreshedDocument = sha2FileCacheDataLoader.getRefreshedDocument("tl_refresh.xml");
        assertNotEquals(((DocumentWithSha2) document).getDocument().getDigest(DigestAlgorithm.SHA256), refreshedDocument.getDigest(DigestAlgorithm.SHA256));
    }

    @Test
    public void nullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new Sha2FileCacheDataLoader().getDocument(null));
        assertEquals("DSSCacheFileLoader shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new Sha2FileCacheDataLoader(null).getDocument(null));
        assertEquals("DSSCacheFileLoader shall be provided!", exception.getMessage());

        Sha2FileCacheDataLoader sha2FileCacheDataLoader = new Sha2FileCacheDataLoader(fileDataLoader);

        exception = assertThrows(NullPointerException.class, () -> sha2FileCacheDataLoader.getDocument(null));
        assertEquals("Predicate shall be provided!", exception.getMessage());

        sha2FileCacheDataLoader.setPredicate(predicate);

        assertNull(sha2FileCacheDataLoader.getDocument(null));
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
