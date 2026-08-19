package eu.europa.esig.dss.lote.json.job;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.json.MockDataLoader;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.sync.LoTEExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.cache.CacheCleaner;
import eu.europa.esig.dss.validation.job.cache.state.CacheStateEnum;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonLoLoTEValidationJobTest {
    
    private static final String LOLOTE_LOCATION = "http://dss.nowina.lu/lolote.json";
    private static final String PID_PROVIDERS_LOCATION = "https://test.test/lote-pid";

    private static final String LOLOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUlistofthelists";

    private static LoTEValidationJob loteValidationJob;
    private static CacheCleaner cacheCleaner;
    private static FileCacheDataLoader offlineFileLoader;
    private static FileCacheDataLoader onlineFileLoader;

    private static Map<String, DSSDocument> urlMap;

    private static CertificateToken loloteSigner;

    private static File cacheDirectory;

    @BeforeAll
    static void initBeforeAll() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        offlineFileLoader.setFileCacheDirectory(cacheDirectory);

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        cacheCleaner = new CacheCleaner();
        cacheCleaner.setDSSFileLoader(offlineFileLoader);
        cacheCleaner.setCleanFileSystem(true);

        loloteSigner = DSSUtils.loadCertificate(new File("src/test/resources/lolote-cert.cer"));
    }

    @BeforeEach
    void init() {
        populateMap();
    }

    private void populateMap() {
        urlMap.put(LOLOTE_LOCATION, new FileDocument("src/test/resources/eu-lolote.json"));
        urlMap.put(PID_PROVIDERS_LOCATION, new FileDocument("src/test/resources/pid-providers.json"));
    }

    @Test
    void loloteTest() {
        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(1, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> otherLoTEInfos = summary.getOtherLoTEInfos();
        assertEquals(0, otherLoTEInfos.size());

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        assertEquals(1, loloteInfos.size());

        LoLoTEInfo loloteInfo = loloteInfos.get(0);
        List<CertificateToken> potentialSigners = loloteInfo.getValidationCacheInfo().getPotentialSigners();
        assertTrue(Utils.isCollectionNotEmpty(potentialSigners));
        assertEquals(1, potentialSigners.size());
        assertEquals(loloteSigner, potentialSigners.get(0));

        assertNotNull(loloteInfo.getDownloadCacheInfo());
        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertTrue(loloteInfo.getDownloadCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getDownloadCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getDownloadCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getDownloadCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getDownloadCacheInfo().isError());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime(), loloteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertEquals(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime(), loloteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getDownloadCacheInfo().getStatusName());

        assertNotNull(loloteInfo.getParsingCacheInfo());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertTrue(loloteInfo.getParsingCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getParsingCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getParsingCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getParsingCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNotNull(loloteInfo.getParsingCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getParsingCacheInfo().getLastStateTransitionTime(), loloteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getParsingCacheInfo().getStatusName());

        assertNotNull(loloteInfo.getValidationCacheInfo());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertTrue(loloteInfo.getValidationCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getValidationCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getValidationCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getValidationCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getValidationCacheInfo().isError());
        assertNotNull(loloteInfo.getValidationCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getValidationCacheInfo().getLastStateTransitionTime(), loloteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getValidationCacheInfo().getStatusName());

        List<LoTEInfo> loteInfos = loloteInfo.getChildrenInfos();
        assertEquals(1, loteInfos.size());

        for (LoTEInfo loteInfo : loteInfos) {
            assertTrue(loteInfo.getDownloadCacheInfo().isResultExist());
            assertTrue(loteInfo.getDownloadCacheInfo().isSynchronized());
            assertNull(loteInfo.getDownloadCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getDownloadCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(loteInfo.getParsingCacheInfo().isSynchronized());
            assertNull(loteInfo.getParsingCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getParsingCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getParsingCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(loteInfo.getValidationCacheInfo().isSynchronized());
            assertNull(loteInfo.getValidationCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getValidationCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getValidationCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(Utils.isCollectionNotEmpty(loteInfo.getValidationCacheInfo().getPotentialSigners()));
        }
    }

    @Test
    void loloteGetSummaryFromCertificateSourceTest() {
        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = trustedEntitiesCertificateSource.getSummary();

        assertEquals(1, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> otherLoTEInfos = summary.getOtherLoTEInfos();
        assertEquals(0, otherLoTEInfos.size());

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        assertEquals(1, loloteInfos.size());

        LoLoTEInfo loloteInfo = loloteInfos.get(0);
        List<CertificateToken> potentialSigners = loloteInfo.getValidationCacheInfo().getPotentialSigners();
        assertTrue(Utils.isCollectionNotEmpty(potentialSigners));
        assertEquals(1, potentialSigners.size());
        assertEquals(loloteSigner, potentialSigners.get(0));

        assertNotNull(loloteInfo.getDownloadCacheInfo());
        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertTrue(loloteInfo.getDownloadCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getDownloadCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getDownloadCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getDownloadCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getDownloadCacheInfo().isError());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime(), loloteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertEquals(loloteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime(), loloteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getDownloadCacheInfo().getStatusName());

        assertNotNull(loloteInfo.getParsingCacheInfo());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertTrue(loloteInfo.getParsingCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getParsingCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getParsingCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getParsingCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNotNull(loloteInfo.getParsingCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getParsingCacheInfo().getLastStateTransitionTime(), loloteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getParsingCacheInfo().getStatusName());

        assertNotNull(loloteInfo.getValidationCacheInfo());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertTrue(loloteInfo.getValidationCacheInfo().isSynchronized());
        assertFalse(loloteInfo.getValidationCacheInfo().isDesynchronized());
        assertFalse(loloteInfo.getValidationCacheInfo().isRefreshNeeded());
        assertFalse(loloteInfo.getValidationCacheInfo().isToBeDeleted());
        assertFalse(loloteInfo.getValidationCacheInfo().isError());
        assertNotNull(loloteInfo.getValidationCacheInfo().getLastStateTransitionTime());
        assertNotNull(loloteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loloteInfo.getValidationCacheInfo().getLastStateTransitionTime(), loloteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(CacheStateEnum.SYNCHRONIZED.name(), loloteInfo.getValidationCacheInfo().getStatusName());

        List<LoTEInfo> loteInfos = loloteInfo.getChildrenInfos();
        assertEquals(1, loteInfos.size());

        for (LoTEInfo loteInfo : loteInfos) {
            assertTrue(loteInfo.getDownloadCacheInfo().isResultExist());
            assertTrue(loteInfo.getDownloadCacheInfo().isSynchronized());
            assertNull(loteInfo.getDownloadCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getDownloadCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(loteInfo.getParsingCacheInfo().isSynchronized());
            assertNull(loteInfo.getParsingCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getParsingCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getParsingCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getParsingCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(loteInfo.getValidationCacheInfo().isSynchronized());
            assertNull(loteInfo.getValidationCacheInfo().getExceptionMessage());
            assertNull(loteInfo.getValidationCacheInfo().getExceptionStackTrace());
            assertNotNull(loteInfo.getValidationCacheInfo().getLastStateTransitionTime());
            assertNotNull(loteInfo.getValidationCacheInfo().getLastSuccessSynchronizationTime());
            assertTrue(Utils.isCollectionNotEmpty(loteInfo.getValidationCacheInfo().getPotentialSigners()));
        }
    }

    @Test
    void emptyLoLoTETest() {
        LoTEValidationJob validationJob = new LoTEValidationJob();
        validationJob.setOfflineDataLoader(offlineFileLoader);
        validationJob.setOnlineDataLoader(onlineFileLoader);
        validationJob.setCacheCleaner(cacheCleaner);
        validationJob.setLoLoTESources(new LoLoTESource());
        Exception exception = assertThrows(NullPointerException.class, validationJob::offlineRefresh);
        assertEquals("URL cannot be null.", exception.getMessage());
    }

    @Test
    void loloteGeSummaryTimeoutTest() {
        LoTEValidationJob validationJob = getValidationJob();
        assertTimeout(ofMillis(50), validationJob::getSummary);
    }

    @Test
    void loloteBrokenSigTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-broken-sig.json");

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptInvalidListOfLists(false);
        synchronizationStrategy.setAcceptInvalidList(false);
        synchronizationStrategy.setAcceptExpiredListOfLists(true);
        synchronizationStrategy.setAcceptExpiredList(true);

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_FAILED, loloteInfo.getValidationCacheInfo().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, loloteInfo.getValidationCacheInfo().getSubIndication());
        assertNotNull(loloteInfo.getValidationCacheInfo().getSigningTime());
        assertNotNull(loloteInfo.getValidationCacheInfo().getSigningCertificate());

        assertEquals(1, loloteInfo.getChildrenInfos().size());
        assertFalse(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));

        updateLoLoTELocation("src/test/resources/eu-lolote.json");

        loteValidationJob.onlineRefresh();

        summary = loteValidationJob.getSummary();

        loloteInfos = summary.getLoLoTEInfos();
        loloteInfo = loloteInfos.get(0);

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_PASSED, loloteInfo.getValidationCacheInfo().getIndication());

        assertEquals(1, loloteInfo.getChildrenInfos().size());
        assertTrue(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteBrokenSigAcceptAllTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-broken-sig.json");

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptInvalidListOfLists(true);
        synchronizationStrategy.setAcceptInvalidList(true);
        synchronizationStrategy.setAcceptExpiredListOfLists(true);
        synchronizationStrategy.setAcceptExpiredList(true);

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_FAILED, loloteInfo.getValidationCacheInfo().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, loloteInfo.getValidationCacheInfo().getSubIndication());
        assertNotNull(loloteInfo.getValidationCacheInfo().getSigningTime());
        assertNotNull(loloteInfo.getValidationCacheInfo().getSigningCertificate());

        assertEquals(1, loloteInfo.getChildrenInfos().size());
        assertTrue(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));

        updateLoLoTELocation("src/test/resources/eu-lolote.json");

        loteValidationJob.onlineRefresh();

        summary = loteValidationJob.getSummary();

        loloteInfos = summary.getLoLoTEInfos();
        loloteInfo = loloteInfos.get(0);

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_PASSED, loloteInfo.getValidationCacheInfo().getIndication());

        assertEquals(1, loloteInfo.getChildrenInfos().size());
        assertTrue(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void brokenLoTESigTest() {
        updateLoTELocation("src/test/resources/pid-providers-broken-sig.json");

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptInvalidListOfLists(false);
        synchronizationStrategy.setAcceptInvalidList(false);
        synchronizationStrategy.setAcceptExpiredListOfLists(true);
        synchronizationStrategy.setAcceptExpiredList(true);

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();
        
        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        assertEquals(1, loloteInfos.size());
        LoLoTEInfo loloteInfo = loloteInfos.get(0);
        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));

        updateLoTELocation("src/test/resources/pid-providers.json");

        loteValidationJob.onlineRefresh();
        summary = loteValidationJob.getSummary();

        loloteInfos = summary.getLoLoTEInfos();
        assertEquals(1, loloteInfos.size());
        loloteInfo = loloteInfos.get(0);
        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertEquals(17, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteNotParsableTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-not-parsable.json");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertEquals(0, loloteInfo.getChildrenInfos().size());

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertFalse(loloteInfo.getDownloadCacheInfo().isError());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getParsingCacheInfo().isResultExist());
        assertTrue(loloteInfo.getParsingCacheInfo().isError());
        assertNotNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNotNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNotNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNotNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteNotCompliantTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-not-compliant.json");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(Utils.isCollectionNotEmpty(loloteInfo.getParsingCacheInfo().getStructureValidationMessages()));
        assertTrue(loloteInfo.getParsingCacheInfo().getStructureValidationMessages().stream().anyMatch(m -> m.contains("LoTEVersionIdentifier")));
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(17, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteNoSigTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-no-sig.json");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertEquals(0, loloteInfo.getChildrenInfos().size());

        assertFalse(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertTrue(loloteInfo.getDownloadCacheInfo().isError());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertEquals("The document obtained from URL 'http://dss.nowina.lu/lolote.json' is " +
                "not a valid JWS Compact Serialization signature!", loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteJsonSerializationTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-json-serialization.json");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertEquals(0, loloteInfo.getChildrenInfos().size());

        assertFalse(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertTrue(loloteInfo.getDownloadCacheInfo().isError());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertEquals("The document obtained from URL 'http://dss.nowina.lu/lolote.json' is " +
                "not a valid JWS Compact Serialization signature!", loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNotNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void loloteUpdateTest() {
        updateLoLoTELocation("src/test/resources/eu-lolote-not-compliant.json");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        LoLoTEInfo loloteInfo = loloteInfos.get(0);

        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(Utils.isCollectionNotEmpty(loloteInfo.getParsingCacheInfo().getStructureValidationMessages()));
        assertTrue(loloteInfo.getParsingCacheInfo().getStructureValidationMessages().stream().anyMatch(m -> m.contains("LoTEVersionIdentifier")));
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(17, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));

        updateLoLoTELocation("src/test/resources/eu-lolote.json");

        loteValidationJob.onlineRefresh();
        summary = loteValidationJob.getSummary();

        loloteInfos = summary.getLoLoTEInfos();
        loloteInfo = loloteInfos.get(0);

        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertTrue(loloteInfo.getDownloadCacheInfo().isResultExist());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(loloteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loloteInfo.getParsingCacheInfo().isError());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(Utils.isCollectionNotEmpty(loloteInfo.getParsingCacheInfo().getStructureValidationMessages()));
        assertTrue(loloteInfo.getValidationCacheInfo().isResultExist());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionMessage());
        assertNull(loloteInfo.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(17, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    private LoLoTESource getLoLoTESource() {
        LoLoTESource loloteSource = new LoLoTESource();
        loloteSource.setUrl(LOLOTE_LOCATION);
        CertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(loloteSigner);
        loloteSource.setCertificateSource(trustedCertificateSource);
        loloteSource.setLolotePredicate(otherListPointer -> LOLOTE_TYPE.equals(otherListPointer.getType()));
        loloteSource.setLotePredicate(otherListPointer -> !LOLOTE_TYPE.equals(otherListPointer.getType()));
        return loloteSource;
    }

    private LoTEValidationJob getValidationJob() {
        return getValidationJob(new TrustedEntitiesCertificateSource());
    }

    private LoTEValidationJob getValidationJob(TrustedEntitiesCertificateSource trustedEntitiesCertificateSource) {
        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setOnlineDataLoader(onlineFileLoader);
        loteValidationJob.setLoLoTESources(getLoLoTESource());
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.setCacheCleaner(cacheCleaner);
        return loteValidationJob;
    }

    private void updateLoLoTELocation(String fileLocation) {
        if (fileLocation != null) {
            urlMap.put(LOLOTE_LOCATION, new FileDocument(fileLocation));
        }
    }

    private void updateLoTELocation(String fileLocation) {
        if (fileLocation != null) {
            urlMap.put(PID_PROVIDERS_LOCATION, new FileDocument(fileLocation));
        }
    }

    @AfterEach
    void clean() throws IOException {
        File cacheDirectory = new File("target/cache");
        cacheDirectory.mkdirs();
        Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
    }
    
}
