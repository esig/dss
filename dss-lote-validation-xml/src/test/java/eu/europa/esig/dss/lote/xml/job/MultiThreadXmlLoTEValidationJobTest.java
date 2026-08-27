package eu.europa.esig.dss.lote.xml.job;

import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.xml.MockDataLoader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.job.cache.CacheCleaner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@Tag("slow")
class MultiThreadXmlLoTEValidationJobTest {

    private static final Logger LOG = LoggerFactory.getLogger(MultiThreadXmlLoTEValidationJobTest.class);

    private static File cacheDirectory;

    private static LoTEValidationJob loteValidationJob;
    private static CacheCleaner cacheCleaner;
    private static FileCacheDataLoader offlineFileLoader;
    private static FileCacheDataLoader onlineFileLoader;

    private static final String PID_LOTE_URL = "https://test.test/lote";
    private static LoTESource loteSource;
    private static CertificateToken loteSigningCertificate;

    @BeforeAll
    static void init() {
        Map<String, DSSDocument> urlMap = new HashMap<>();
        urlMap.put(PID_LOTE_URL, new FileDocument("src/test/resources/lote-pubeaa.xml"));

        cacheDirectory = new File("target/cache-slow");

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

        loteValidationJob = new LoTEValidationJob();
        loteValidationJob.setOfflineDataLoader(offlineFileLoader);
        loteValidationJob.setOnlineDataLoader(onlineFileLoader);
        loteValidationJob.setCacheCleaner(cacheCleaner);

        loteSource = new LoTESource();
        loteSource.setUrl(PID_LOTE_URL);
        CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
        loteSigningCertificate = DSSUtils.loadCertificate(new File("src/test/resources/lolote-cert.cer"));
        commonTrustedCertificateSource.addCertificate(loteSigningCertificate);
        loteSource.setCertificateSource(commonTrustedCertificateSource);
        loteSource.setTrustedEntityPredicate(t -> true);
        loteSource.setTrustedServicePredicate(t -> true);
        loteValidationJob.setLoTESources(loteSource);
    }

    @Test
    void test() {

        ExecutorService executor = Executors.newFixedThreadPool(40);

        List<Future<LoTEValidationJobSummary>> futuresValidationResult = new ArrayList<>();
        List<Future<?>> futuresOfflineRefresh = new ArrayList<>();
        List<Future<?>> futuresOnlineRefresh = new ArrayList<>();

        for (int i = 0; i < 100; i++) {
            futuresValidationResult.add(executor.submit(new ValidationJobSummeryConcurrent()));
            futuresOfflineRefresh.add(executor.submit(new OfflineRefreshConcurrent()));
            futuresOnlineRefresh.add(executor.submit(new OnlineRefreshConcurrent()));
        }

        for (Future<LoTEValidationJobSummary> future : futuresValidationResult) {
            LoTEValidationJobSummary jobSummary = null;
            try {
                jobSummary = future.get();
            } catch (Exception e) {
                LOG.error("Cannot retrieve validation job result", e);
            }
            assertNotNull(jobSummary);
        }

        executor.shutdown();

    }

    private static class ValidationJobSummeryConcurrent implements Callable<LoTEValidationJobSummary> {
        ValidationJobSummeryConcurrent() {
        }
        @Override
        public LoTEValidationJobSummary call() {
            return loteValidationJob.getSummary();
        }
    }

    private static class OfflineRefreshConcurrent implements Callable<Boolean> {
        @Override
        public Boolean call() {
            loteValidationJob.offlineRefresh();
            return true;
        }
    }

    private static class OnlineRefreshConcurrent implements Callable<Boolean> {
        @Override
        public Boolean call() {
            loteValidationJob.onlineRefresh();
            return true;
        }
    }

    @AfterEach
    void clean() throws IOException {
        cacheDirectory.mkdirs();
        Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
    }

}
