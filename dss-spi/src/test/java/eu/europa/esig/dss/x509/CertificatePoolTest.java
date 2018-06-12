package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
	public void test() throws InterruptedException, ExecutionException {

		final ExecutorService threadPool = Executors.newFixedThreadPool(NB_THREADS);
		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();

		for (int i = 0; i < NB_THREADS; i++) {
			futures.add(threadPool.submit(new Callable<Boolean>() {

				@Override
				public Boolean call() throws Exception {
					CertificatePool pool = new CertificatePool();
					pool.merge(ORIGINAL_POOL);
					final boolean positiveNumber = pool.getNumberOfCertificates() > 0;
					final boolean foundCert = Utils
							.isCollectionNotEmpty(pool.get(EXPECTED_TOKEN.getSubjectX500Principal()));
					return positiveNumber && foundCert;
				}

			}));
		}

		for (Future<Boolean> future : futures) {
			assertTrue(future.get());
		}
	}

}
