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

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CountDownLatchWithErrorTest {

    private static final Logger LOG = LoggerFactory.getLogger(CountDownLatchWithErrorTest.class);

    @Test
    void test() {
        ExecutorService executorService = Executors.newFixedThreadPool(3);
        CountDownLatch latch = new CountDownLatch(3);

        TLAnalysis tlTask = new TLAnalysis(null, null, null, latch);
        assertNotNull(tlTask);
        executorService.submit(tlTask);

        LOTLAnalysis lotlTask = new LOTLAnalysis(null, null, null, latch);
        assertNotNull(lotlTask);
        executorService.submit(lotlTask);

        LOTLWithPivotsAnalysis lotlWithPivotsTask = new LOTLWithPivotsAnalysis(null, null, null, null, latch);
        assertNotNull(lotlWithPivotsTask);
        executorService.submit(lotlWithPivotsTask);

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertEquals(0, latch.getCount());

        shutdownNowAndAwaitTermination(executorService);
    }

    private void shutdownNowAndAwaitTermination(ExecutorService executorService) {
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

}
