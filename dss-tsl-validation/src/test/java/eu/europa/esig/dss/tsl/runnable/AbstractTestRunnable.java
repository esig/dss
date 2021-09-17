package eu.europa.esig.dss.tsl.runnable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class AbstractTestRunnable {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractTestRunnable.class);

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

}
