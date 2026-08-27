package eu.europa.esig.dss.lote.xml.job;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.sync.LoTEExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.lote.xml.MockDataLoader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.lote.ServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.model.lote.TrustedProperties;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.cache.CacheCleaner;
import eu.europa.esig.dss.validation.job.sync.AcceptAllStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEValidationJobTest {

    private static final String PUBEAA_LOCATION = "http://dss.nowina.lu/lote-pubeaa.xml";

    private static LoTEValidationJob loteValidationJob;
    private static CacheCleaner cacheCleaner;
    private static FileCacheDataLoader offlineFileLoader;
    private static FileCacheDataLoader onlineFileLoader;

    private static Map<String, DSSDocument> urlMap;

    private static CertificateToken pubeaaSigner;

    private static File cacheDirectory;

    @BeforeAll
    static void initBeforeAll() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        offlineFileLoader.setFileCacheDirectory(cacheDirectory);

        Map<String, DSSDocument> onlineMap = new HashMap<>(urlMap);

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(onlineMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        cacheCleaner = new CacheCleaner();
        cacheCleaner.setDSSFileLoader(offlineFileLoader);
        cacheCleaner.setCleanFileSystem(true);

        pubeaaSigner = DSSUtils.loadCertificate(new File("src/test/resources/lote-signer.cer"));
    }

    @BeforeEach
    void init() {
        populateMap();
    }

    private void populateMap() {
        urlMap.put(PUBEAA_LOCATION, new FileDocument("src/test/resources/lote-pubeaa.xml"));
    }

    @Test
    void pubeaaListTest() {
        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();
        assertEquals(1, summary.getOtherLoTEInfos().size());

        LoTEInfo loteInfo = summary.getOtherLoTEInfos().get(0);
        assertTrue(loteInfo.getDownloadCacheInfo().isResultExist());
        assertFalse(loteInfo.getDownloadCacheInfo().isError());
        assertTrue(loteInfo.getParsingCacheInfo().isResultExist());
        assertFalse(loteInfo.getParsingCacheInfo().isError());
        assertFalse(Utils.isCollectionNotEmpty(loteInfo.getParsingCacheInfo().getStructureValidationMessages()));
        assertEquals(1, loteInfo.getParsingCacheInfo().getTrustedEntitiesNumber());
        assertEquals(1, loteInfo.getParsingCacheInfo().getTrustedServicesNumber());
        assertEquals(1, loteInfo.getParsingCacheInfo().getCertNumber());
        assertTrue(loteInfo.getValidationCacheInfo().isResultExist());
        assertFalse(loteInfo.getValidationCacheInfo().isError());
        assertEquals(Indication.TOTAL_PASSED, loteInfo.getValidationCacheInfo().getIndication());
    }

    @Test
    void getSummaryFromCertificateSourceTest() {
        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(getPUBEAAProviderListSource());
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = trustedEntitiesCertificateSource.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> LoTEInfos = summary.getOtherLoTEInfos();
        assertEquals(1, LoTEInfos.size());

        LoTEInfo pidLoTE = LoTEInfos.get(0);
        assertNotNull(pidLoTE.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertFalse(pidLoTE.getDownloadCacheInfo().getLastSuccessSynchronizationTime().after(pidLoTE.getDownloadCacheInfo().getLastStateTransitionTime()));

        assertTrue(pidLoTE.getDownloadCacheInfo().isSynchronized());
        assertTrue(pidLoTE.getParsingCacheInfo().isSynchronized());
        assertTrue(pidLoTE.getValidationCacheInfo().isSynchronized());

        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertNotNull(pidLoTE.getUrl());

        assertNotNull(pidLoTE.getParsingCacheInfo().getSequenceNumber());
        assertNotNull(pidLoTE.getParsingCacheInfo().getVersion());
        assertEquals("EU", pidLoTE.getParsingCacheInfo().getTerritory());
        assertNotNull(pidLoTE.getParsingCacheInfo().getIssueDate());
        assertNotNull(pidLoTE.getParsingCacheInfo().getNextUpdateDate());
        assertTrue(pidLoTE.getParsingCacheInfo().getIssueDate().before(pidLoTE.getParsingCacheInfo().getNextUpdateDate()));
        assertNotNull(pidLoTE.getParsingCacheInfo().getDistributionPoints());
        List<String> czDistributionPoints = pidLoTE.getParsingCacheInfo().getDistributionPoints();
        assertThrows(UnsupportedOperationException.class, () -> czDistributionPoints.add("bla"));
        assertNotNull(pidLoTE.getParsingCacheInfo().getTrustedEntities());
        assertEquals(1, pidLoTE.getParsingCacheInfo().getTrustedEntities().size());
        List<TrustedEntity> trustedEntities = pidLoTE.getParsingCacheInfo().getTrustedEntities();
        TrustedEntity emptyTrustedEntity = new TrustedEntity();
        assertThrows(UnsupportedOperationException.class, () -> trustedEntities.add(emptyTrustedEntity));
        assertEquals(1, pidLoTE.getParsingCacheInfo().getTrustedEntities().size());

        TrustedEntity trustedEntity = pidLoTE.getParsingCacheInfo().getTrustedEntities().get(0);
        Map<String, List<String>> electronicAddresses = trustedEntity.getElectronicAddresses();
        String key = "bla";
        List<String> emptyList = Collections.emptyList();
        assertThrows(UnsupportedOperationException.class, () -> electronicAddresses.put(key, emptyList));
        Map<String, List<String>> names = trustedEntity.getNames();
        assertThrows(UnsupportedOperationException.class, () -> names.put(key, emptyList));
        Map<String, List<String>> tradeNames = trustedEntity.getTradeNames();
        assertThrows(UnsupportedOperationException.class, () -> tradeNames.put(key, emptyList));
        Map<String, List<String>> information = trustedEntity.getInformation();
        assertThrows(UnsupportedOperationException.class, () -> information.put(key, Collections.singletonList(key)));
        Map<String, String> postalAddresses = trustedEntity.getPostalAddresses();
        assertThrows(UnsupportedOperationException.class, () -> postalAddresses.put(key, "value"));
        List<String> registrationIdentifiers = trustedEntity.getRegistrationIdentifiers();
        assertThrows(UnsupportedOperationException.class, () -> registrationIdentifiers.add(key));
        List<TrustedEntityService> services = trustedEntity.getServices();
        TrustedEntityService trustService1 = trustedEntity.getServices().get(0);
        assertThrows(UnsupportedOperationException.class, () -> services.add(trustService1));

        TrustedEntityService trustService = trustedEntity.getServices().get(0);
        List<CertificateToken> certificates = trustService.getCertificates();
        assertThrows(UnsupportedOperationException.class, () -> certificates.add(pubeaaSigner));

        TimeDependentValues<ServiceStatusAndInformationExtensions> timeDependentValues = trustService.getStatusAndInformationExtensions();
        ServiceStatusAndInformationExtensions latest = timeDependentValues.getLatest();
        Map<String, List<String>> latestNames = latest.getNames();
        assertThrows(UnsupportedOperationException.class, () -> latestNames.put(key, emptyList));
        List<String> serviceSupplyPoints = latest.getServiceSupplyPoints();
        assertThrows(UnsupportedOperationException.class, () -> serviceSupplyPoints.add(key));

        assertTrue(pidLoTE.getValidationCacheInfo().isValid());
        assertEquals(Indication.TOTAL_PASSED, pidLoTE.getValidationCacheInfo().getIndication());
        assertNull(pidLoTE.getValidationCacheInfo().getSubIndication());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningTime());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningCertificate());
        assertEquals(pubeaaSigner, pidLoTE.getValidationCacheInfo().getSigningCertificate());
    }

    @Test
    void trustTimeExtractAllTest() {
        LoTESource pubeaaLoTESource = getPUBEAAProviderListSource();

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(pubeaaLoTESource);
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.setCacheCleaner(cacheCleaner);
        loteValidationJob.offlineRefresh();

        assertEquals(1, trustedEntitiesCertificateSource.getCertificates().size());

        Calendar calendar = Calendar.getInstance();
        calendar.set(2026, Calendar.JULY, 1);
        Date controlTime = calendar.getTime();

        int validCertsCounter = 0;
        int invalidCertsCounter = 0;
        for (CertificateToken certificateToken : trustedEntitiesCertificateSource.getCertificates()) {
            assertTrue(trustedEntitiesCertificateSource.isTrusted(certificateToken));

            CertificateTrustTime trustTime = trustedEntitiesCertificateSource.getTrustTime(certificateToken);
            assertNotNull(trustTime);
            assertTrue(trustTime.isTrusted());

            if (trustedEntitiesCertificateSource.isTrustedAtTime(certificateToken, controlTime)) {
                assertTrue(trustTime.isTrusted());
                assertTrue(trustTime.isTrustedAtTime(controlTime));
                assertNull(trustTime.getStartDate());
                assertNull(trustTime.getEndDate());
                ++validCertsCounter;
            } else {
                ++invalidCertsCounter;
            }

            List<TrustedProperties> trustedProperties = trustedEntitiesCertificateSource.getTrustedProperties(certificateToken);
            assertEquals(1, trustedProperties.size());

            Set<CertificateToken> crossCerts = trustedEntitiesCertificateSource.getByPublicKey(certificateToken.getPublicKey());
            assertEquals(1, crossCerts.size());

            Set<CertificateToken> bySubject = trustedEntitiesCertificateSource.getBySubject(certificateToken.getSubject());
            assertEquals(1, bySubject.size());

            Set<CertificateToken> equivalentCerts = trustedEntitiesCertificateSource.getByEntityKey(certificateToken.getEntityKey());
            assertEquals(1, equivalentCerts.size());

        }
        assertEquals(1, validCertsCounter);
        assertEquals(0, invalidCertsCounter);

    }

    @Test
    void trustAnchorValidityPredicateTest() {
        LoTESource pubeaaLoTESource = getPUBEAAProviderListSource();
        pubeaaLoTESource.setTrustAnchorValidityPredicate(serviceStatusAndInformationExtensions ->
                serviceStatusAndInformationExtensions.getNames().values().stream()
                        .anyMatch(k -> k.stream()
                                .anyMatch(v -> Utils.endsWithIgnoreCase(v, "Entity 1"))));

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(pubeaaLoTESource);
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        assertEquals(1, trustedEntitiesCertificateSource.getCertificates().size());

        Calendar calendar = Calendar.getInstance();
        calendar.set(2026, Calendar.JANUARY, 1);
        Date controlTime = calendar.getTime();

        int validCertsCounter = 0;
        int expiredCertsCounter = 0;
        int invalidCertsCounter = 0;
        for (CertificateToken certificateToken : trustedEntitiesCertificateSource.getCertificates()) {
            CertificateTrustTime trustTime = trustedEntitiesCertificateSource.getTrustTime(certificateToken);
            assertNotNull(trustTime);

            if (trustedEntitiesCertificateSource.isTrusted(certificateToken)) {
                assertTrue(trustTime.isTrusted());

                if (trustedEntitiesCertificateSource.isTrustedAtTime(certificateToken, controlTime)) {
                    assertTrue(trustTime.isTrustedAtTime(controlTime));
                    ++validCertsCounter;
                } else {
                    assertFalse(trustTime.isTrustedAtTime(controlTime));
                    ++expiredCertsCounter;
                }

            } else {
                assertFalse(trustTime.isTrusted());
                assertFalse(trustTime.isTrustedAtTime(controlTime));
                assertFalse(trustedEntitiesCertificateSource.isTrustedAtTime(certificateToken, controlTime));
                ++invalidCertsCounter;
            }

        }
        assertEquals(1, validCertsCounter);
        assertEquals(0, expiredCertsCounter);
        assertEquals(0, invalidCertsCounter);
        assertEquals(1, validCertsCounter + expiredCertsCounter + invalidCertsCounter);

        pubeaaLoTESource.setTrustAnchorValidityPredicate(serviceStatusAndInformationExtensions ->
                serviceStatusAndInformationExtensions.getNames().values().stream()
                        .anyMatch(k -> k.stream()
                                .anyMatch(v -> Utils.endsWithIgnoreCase(v, "Entity 2"))));

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(pubeaaLoTESource);
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.offlineRefresh();

        assertEquals(1, trustedEntitiesCertificateSource.getCertificates().size());

        validCertsCounter = 0;
        expiredCertsCounter = 0;
        invalidCertsCounter = 0;
        for (CertificateToken certificateToken : trustedEntitiesCertificateSource.getCertificates()) {
            CertificateTrustTime trustTime = trustedEntitiesCertificateSource.getTrustTime(certificateToken);
            assertNotNull(trustTime);

            if (trustedEntitiesCertificateSource.isTrusted(certificateToken)) {
                assertTrue(trustTime.isTrusted());

                if (trustedEntitiesCertificateSource.isTrustedAtTime(certificateToken, controlTime)) {
                    assertTrue(trustTime.isTrustedAtTime(controlTime));
                    ++validCertsCounter;
                } else {
                    assertFalse(trustTime.isTrustedAtTime(controlTime));
                    ++expiredCertsCounter;
                }

            } else {
                assertFalse(trustTime.isTrusted());
                assertFalse(trustTime.isTrustedAtTime(controlTime));
                assertFalse(trustedEntitiesCertificateSource.isTrustedAtTime(certificateToken, controlTime));
                ++invalidCertsCounter;
            }

        }
        assertEquals(0, validCertsCounter);
        assertEquals(0, expiredCertsCounter);
        assertEquals(1, invalidCertsCounter);
        assertEquals(1, validCertsCounter + expiredCertsCounter + invalidCertsCounter);
    }

    @Test
    void testNoSynchronization() {
        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(getPUBEAAProviderListSource());
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);
        assertTrue(pidLoTE.getDownloadCacheInfo().isDesynchronized());
        assertTrue(pidLoTE.getParsingCacheInfo().isDesynchronized());
        assertTrue(pidLoTE.getValidationCacheInfo().isDesynchronized());
        assertFalse(pidLoTE.getDownloadCacheInfo().isSynchronized());
        assertFalse(pidLoTE.getParsingCacheInfo().isSynchronized());
        assertFalse(pidLoTE.getValidationCacheInfo().isSynchronized());
    }

    @Test
    void emptyLoTETest() {
        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setCacheCleaner(cacheCleaner);
        loteValidationJob.setLoTESources(new LoTESource());

        Exception exception = assertThrows(NullPointerException.class, () -> loteValidationJob.offlineRefresh());
        assertEquals("URL cannot be null.", exception.getMessage());
    }

    @Test
    void brokenSigTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-broken-sig.xml");

        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_FAILED, pidLoTE.getValidationCacheInfo().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, pidLoTE.getValidationCacheInfo().getSubIndication());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningTime());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningCertificate());
        assertEquals(pubeaaSigner, pidLoTE.getValidationCacheInfo().getSigningCertificate());
    }

    @Test
    void brokenSigWithSyncStrategyTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-broken-sig.xml");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setCacheExpirationTime(0);
        fileCacheDataLoader.setDataLoader(new MockDataLoader(urlMap));
        fileCacheDataLoader.setFileCacheDirectory(cacheDirectory);

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptInvalidList(false);
        synchronizationStrategy.setAcceptExpiredList(true);

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setOnlineDataLoader(fileCacheDataLoader);
        loteValidationJob.setLoTESources(getPUBEAAProviderListSource());
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_FAILED, pidLoTE.getValidationCacheInfo().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, pidLoTE.getValidationCacheInfo().getSubIndication());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningTime());
        assertNotNull(pidLoTE.getValidationCacheInfo().getSigningCertificate());
        assertEquals(pubeaaSigner, pidLoTE.getValidationCacheInfo().getSigningCertificate());

        assertFalse(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));

        updateLoTELocation("src/test/resources/lote-pubeaa.xml");

        loteValidationJob.onlineRefresh();
        summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        pidLoTE = loteInfos.get(0);

        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertEquals(Indication.TOTAL_PASSED, pidLoTE.getValidationCacheInfo().getIndication());

        assertTrue(Utils.isCollectionNotEmpty(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void emptyContentTest() {
        urlMap.put(PUBEAA_LOCATION, new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY));

        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertFalse(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertTrue(pidLoTE.getDownloadCacheInfo().isError());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getParsingCacheInfo().isResultExist());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());
    }

    @Test
    void notParsableTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-not-parsable.xml");

        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertFalse(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertTrue(pidLoTE.getDownloadCacheInfo().isError());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getParsingCacheInfo().isResultExist());
        assertFalse(pidLoTE.getParsingCacheInfo().isError());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());
    }

    @Test
    void noSignatureTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-no-sig.xml");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(new AcceptAllStrategy<>());
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertTrue(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(pidLoTE.getParsingCacheInfo().isResultExist());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertEquals("Number of signatures must be equal to 1 (currently : 0)", pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertNull(pidLoTE.getValidationCacheInfo().getIndication());
        assertNull(pidLoTE.getValidationCacheInfo().getSubIndication());

        assertEquals(1, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void noSignatureSkipInvalidStrategyTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-no-sig.xml");

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptExpiredList(true);
        synchronizationStrategy.setAcceptInvalidList(false);

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertTrue(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(pidLoTE.getParsingCacheInfo().isResultExist());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertEquals("Number of signatures must be equal to 1 (currently : 0)", pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertNull(pidLoTE.getValidationCacheInfo().getIndication());
        assertNull(pidLoTE.getValidationCacheInfo().getSubIndication());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void twoSignaturesTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-two-sigs.xml");

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(new AcceptAllStrategy<>());
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertTrue(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(pidLoTE.getParsingCacheInfo().isResultExist());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertEquals("Number of signatures must be equal to 1 (currently : 2)", pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertNull(pidLoTE.getValidationCacheInfo().getIndication());
        assertNull(pidLoTE.getValidationCacheInfo().getSubIndication());

        assertEquals(1, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void twoSignaturesSkipInvalidStrategyTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-two-sigs.xml");

        LoTEExpirationAndSignatureCheckStrategy synchronizationStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        synchronizationStrategy.setAcceptExpiredList(true);
        synchronizationStrategy.setAcceptInvalidList(false);

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        loteValidationJob = getValidationJob(trustedEntitiesCertificateSource);
        loteValidationJob.setSynchronizationStrategy(synchronizationStrategy);
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertTrue(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(pidLoTE.getParsingCacheInfo().isResultExist());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertEquals("Number of signatures must be equal to 1 (currently : 2)", pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());

        assertNull(pidLoTE.getValidationCacheInfo().getIndication());
        assertNull(pidLoTE.getValidationCacheInfo().getSubIndication());

        assertEquals(0, Utils.collectionSize(trustedEntitiesCertificateSource.getCertificates()));
    }

    @Test
    void jsonTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa.json");

        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertFalse(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertTrue(pidLoTE.getDownloadCacheInfo().isError());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNotNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getParsingCacheInfo().isResultExist());
        assertFalse(pidLoTE.getParsingCacheInfo().isError());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertFalse(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());
    }

    @Test
    void structureErrorTest() {
        updateLoTELocation("src/test/resources/lote-pubeaa-not-compliant.xml");

        loteValidationJob = getValidationJob();
        loteValidationJob.offlineRefresh();

        LoTEValidationJobSummary summary = loteValidationJob.getSummary();

        assertEquals(0, summary.getNumberOfProcessedLoLoTEs());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());

        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());

        LoTEInfo pidLoTE = loteInfos.get(0);

        assertTrue(pidLoTE.getDownloadCacheInfo().isResultExist());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getDownloadCacheInfo().getExceptionStackTrace());
        assertTrue(pidLoTE.getParsingCacheInfo().isResultExist());
        assertFalse(pidLoTE.getParsingCacheInfo().isError());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getParsingCacheInfo().getExceptionStackTrace());
        assertTrue(Utils.isCollectionNotEmpty(pidLoTE.getParsingCacheInfo().getStructureValidationMessages()));
        assertTrue(pidLoTE.getParsingCacheInfo().getStructureValidationMessages().stream().anyMatch(k -> k.contains("LoTEVersionIdentifier")));
        assertTrue(pidLoTE.getValidationCacheInfo().isResultExist());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionMessage());
        assertNull(pidLoTE.getValidationCacheInfo().getExceptionStackTrace());
    }

    private LoTESource getPUBEAAProviderListSource() {
        LoTESource pidProviderList = new LoTESource();
        pidProviderList.setUrl(PUBEAA_LOCATION);
        CertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(pubeaaSigner);
        pidProviderList.setCertificateSource(trustedCertificateSource);
        return pidProviderList;
    }

    private void updateLoTELocation(String fileLocation) {
        if (fileLocation != null) {
            urlMap.put(PUBEAA_LOCATION, new FileDocument(fileLocation));
        }
    }


    private LoTEValidationJob getValidationJob() {
        return getValidationJob(new TrustedEntitiesCertificateSource());
    }

    private LoTEValidationJob getValidationJob(TrustedEntitiesCertificateSource trustedEntitiesCertificateSource) {
        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setLoTESources(getPUBEAAProviderListSource());
        loteValidationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);
        loteValidationJob.setCacheCleaner(cacheCleaner);
        return loteValidationJob;
    }

    @AfterEach
    void clean() throws IOException {
        cacheDirectory.mkdirs();
        Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
    }

}
