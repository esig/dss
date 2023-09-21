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

public class ZipUtilsTest {

    @Test
    public void concurrencyTest() {
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
