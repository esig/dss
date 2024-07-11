/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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

class TLAnalysisErrorTest extends AbstractTestRunnable {

    @Test
    void test() throws Exception {
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
