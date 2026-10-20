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
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadResult;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingResult;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import eu.europa.esig.dss.validation.job.validation.ValidationResult;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CountDownLatchWithErrorTest extends AbstractTestRunnable {

    @Test
    void test() {
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);

        Runnable taskOne = new MockErrorRunnableAnalysis(null, null, null, latch);
        assertNotNull(taskOne);
        executorService.submit(taskOne);

        Runnable taskTwo = new MockErrorRunnableAnalysis(null, null, null, latch);
        assertNotNull(taskTwo);
        executorService.submit(taskTwo);

        Runnable taskThree = new MockErrorRunnableAnalysis(null, null, null, latch);
        assertNotNull(taskThree);
        executorService.submit(taskThree);

        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertEquals(0, latch.getCount());

        shutdownNowAndAwaitTermination(executorService);
    }

    protected class MockErrorRunnableAnalysis extends AbstractRunnableAnalysis {

        /**
         * Default constructor
         *
         * @param source        {@link DocumentSource}
         * @param cacheAccess   {@link CacheAccessByKey}
         * @param dssFileLoader {@link DSSFileLoader}
         * @param latch         {@link CountDownLatch}
         */
        public MockErrorRunnableAnalysis(DocumentSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
                                         CountDownLatch latch) {
            super(source, cacheAccess, dssFileLoader, latch, null);
        }

        @Override
        protected DSSDocument download(String url) {
            throw new Error("An error occurred during the download task.");
        }

        @Override
        protected DownloadTask getDownloadTask(DSSFileLoader dssFileLoader, String url) {
            return new DownloadTask() {
                @Override
                public DownloadResult get() {
                    throw new RuntimeException("An error occurred during the download task.");
                }
            };
        }
        @Override
        protected ParsingTask getParsingTask(DSSDocument document) {
            return new ParsingTask() {
                @Override
                public ParsingResult get() {
                    return getParsingResult();
                }
            };
        }
        @Override
        protected ValidationTask getValidationTask(DSSDocument document, CertificateSource certificateSource) {
            return new ValidationTask() {
                @Override
                public ValidationResult get() {
                    return getValidationResult(null);
                }
            };
        }

    }

}
