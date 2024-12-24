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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class ZipUtilsTest {

    @Test
    void concurrencyTest() {
        FileDocument asicContainer = new FileDocument("src/test/resources/multifiles-ok.asice");

        ExecutorService executor = Executors.newFixedThreadPool(200);

        List<Future<List<DSSDocument>>> futures = new ArrayList<>();

        for (int i = 0; i < 2000; i++) {
            futures.add(executor.submit(new TestConcurrent(asicContainer)));
        }

        for (Future<List<DSSDocument>> future : futures) {
            try {
                List<DSSDocument> dssDocuments = future.get();
                assertEquals(6, dssDocuments.size());
            } catch (Exception e) {
                fail(e);
            }
        }

        executor.shutdown();
    }

    private static class TestConcurrent implements Callable<List<DSSDocument>> {

        private final DSSDocument asicContainer;

        public TestConcurrent(DSSDocument asicContainer) {
            this.asicContainer = asicContainer;
        }

        @Override
        public List<DSSDocument> call() {
            return ZipUtils.getInstance().extractContainerContent(asicContainer);
        }

    }

}
