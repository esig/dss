package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class CertificatePoolTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePoolTest.class);

	private static final CertificatePool ORIGINAL_POOL;
	private static final CertificateToken EXPECTED_TOKEN;
	private static final int NB_THREADS = 1000;

	static {
		ORIGINAL_POOL = new CertificatePool();
		File resources = new File("src/test/resources");
		File[] certs = resources.listFiles(new FilenameFilter() {

			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".cer") || name.endsWith(".crt") || name.endsWith(".p7c");
			}
		});

		List<CertificateToken> tokens = new ArrayList<CertificateToken>();
		for (File certFile : certs) {
			try (FileInputStream fis = new FileInputStream(certFile)) {
				tokens.addAll(DSSUtils.loadCertificateFromP7c(fis));
			} catch (IOException e) {
				LOG.error("Unable to read file " + certFile.getName());
			}
		}

		LOG.info("Nb certs : " + tokens.size());

		for (CertificateToken certificateToken : tokens) {
			ORIGINAL_POOL.getInstance(certificateToken, CertificateSourceType.OTHER);
		}

		EXPECTED_TOKEN = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
	}

	@Test
	public void test() throws InterruptedException {
		List<Runnable> runnables = new ArrayList<Runnable>();

		for (int i = 0; i < NB_THREADS; i++) {
			runnables.add(new Runnable() {

				@Override
				public void run() {
					CertificatePool pool = new CertificatePool();
					pool.merge(ORIGINAL_POOL);
					assertTrue(pool.getNumberOfCertificates() > 0);
					assertTrue(Utils.isCollectionNotEmpty(pool.get(EXPECTED_TOKEN.getSubjectX500Principal())));
				}
			});
		}

		assertConcurrent("CertificatePool.merge() is not thread-safe", runnables, 2);
	}

	public static void assertConcurrent(final String message, final List<? extends Runnable> runnables, final int maxTimeoutSeconds)
			throws InterruptedException {
		final int numThreads = runnables.size();
		final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<Throwable>());
		final ExecutorService threadPool = Executors.newFixedThreadPool(numThreads);
		try {
			final CountDownLatch allExecutorThreadsReady = new CountDownLatch(numThreads);
			final CountDownLatch afterInitBlocker = new CountDownLatch(1);
			final CountDownLatch allDone = new CountDownLatch(numThreads);
			for (final Runnable submittedTestRunnable : runnables) {
				threadPool.submit(new Runnable() {
					@Override
					public void run() {
						allExecutorThreadsReady.countDown();
						try {
							afterInitBlocker.await();
							submittedTestRunnable.run();
						} catch (final Throwable e) {
							exceptions.add(e);
						} finally {
							allDone.countDown();
						}
					}
				});
			}
			// wait until all threads are ready
			assertTrue("Timeout initializing threads! Perform long lasting initializations before passing runnables to assertConcurrent",
					allExecutorThreadsReady.await(runnables.size() * 10, TimeUnit.MILLISECONDS));
			// start all test runners
			afterInitBlocker.countDown();
			assertTrue(message + " timeout! More than " + maxTimeoutSeconds + " seconds", allDone.await(maxTimeoutSeconds, TimeUnit.SECONDS));
		} finally {
			threadPool.shutdownNow();
		}
		assertTrue(message + " failed with exception(s) " + exceptions, exceptions.isEmpty());
	}

}
