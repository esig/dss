/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.job.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AnalysisErrorTest {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisErrorTest.class);

    @Test
    void test() {
        ExecutorService executorService = Executors.newFixedThreadPool(1);
        CountDownLatch latch = new CountDownLatch(1);

        DocumentSource source = new DocumentSource();
        source.setUrl("LU");

        Runnable process = new MockRunnableAnalysis(source, null, new FileCacheDataLoader(), latch);
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

    protected void shutdownNowAndAwaitTermination(ExecutorService executorService) {
        executorService.shutdownNow();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                LOG.warn("More than 10s to terminate the service executor");
            }
        } catch (InterruptedException e) {
            LOG.warn("Unable to interrupt the service executor", e);
            Thread.currentThread().interrupt();
        }
    }

    private static class MockRunnableAnalysis extends AbstractRunnableAnalysis {

        /**
         * Default constructor
         *
         * @param source        {@link DocumentSource}
         * @param cacheAccess   {@link CacheAccessByKey}
         * @param dssFileLoader {@link DSSFileLoader}
         * @param latch         {@link CountDownLatch}
         */
        public MockRunnableAnalysis(DocumentSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
                                    CountDownLatch latch) {
            super(source, cacheAccess, dssFileLoader, latch);
        }

        @Override
        protected DownloadTask getDownloadTask(DSSFileLoader dssFileLoader, String url) {
            return () -> {
                throw new Error("An error occurred during the download task.");
            };
        }

        @Override
        protected ParsingTask getParsingTask(DSSDocument document) {
            return null;
        }

        @Override
        protected ValidationTask getValidationTask(DSSDocument document, CertificateSource certificateSource) {
            return null;
        }

    }

}
