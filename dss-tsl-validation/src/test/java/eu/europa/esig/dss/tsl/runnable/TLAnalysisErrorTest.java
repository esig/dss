package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.source.TLSource;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TLAnalysisErrorTest extends AbstractTestRunnable {

    @Test
    public void test() throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(1);
        CountDownLatch latch = new CountDownLatch(1);

        TLSource tlSource = new TLSource();
        tlSource.setUrl("LU");

        TLAnalysis process = new MockTLAnalysis(tlSource, null, new FileCacheDataLoader(), latch);
        assertNotNull(process);

        executorService.submit(process);

        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertEquals(0, latch.getCount());

        shutdownNowAndAwaitTermination(executorService);
    }

    private class MockTLAnalysis extends TLAnalysis {

        /**
         * Default constructor
         *
         * @param source        {@link TLSource}
         * @param cacheAccess   {@link CacheAccessByKey}
         * @param dssFileLoader {@link DSSFileLoader}
         * @param latch         {@link CountDownLatch}
         */
        public MockTLAnalysis(TLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
                              CountDownLatch latch) {
            super(source, cacheAccess, dssFileLoader, latch);
        }

        @Override
        protected DSSDocument download(String url) {
            throw new Error("An error occurred during the download task.");
        }

    }

}
