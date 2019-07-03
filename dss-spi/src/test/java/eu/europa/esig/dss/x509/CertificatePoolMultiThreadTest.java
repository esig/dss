package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificatePoolMultiThreadTest {

	@Parameterized.Parameters
	public static Object[][] data() {
		return new Object[5][0];
	}

	public CertificatePoolMultiThreadTest() {
	}

	@Test
	public void testMultiThreads() throws IOException {

		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/extract-tls.p12"), "PKCS12", "ks-password");
		List<CertificateToken> certificates = kscs.getCertificates();

		CertificatePool sharedPool = new CertificatePool();

		ExecutorService executor = Executors.newFixedThreadPool(20);

		List<Future<Integer>> futures = new ArrayList<Future<Integer>>();

		for (int i = 0; i < 100; i++) {
			futures.add(executor.submit(new TestConcurrent(sharedPool, certificates)));

			// not shared
			futures.add(executor.submit(new TestConcurrent(new CertificatePool(), certificates)));
		}

		for (Future<Integer> future : futures) {
			try {
				assertEquals(2438, future.get().intValue());
			} catch (Exception e) {
				fail(e.getMessage());
			}
		}

		executor.shutdown();

	}

	class TestConcurrent implements Callable<Integer> {

		private final CertificatePool sharedPool;
		private final List<CertificateToken> certificates;

		public TestConcurrent(CertificatePool sharedPool, List<CertificateToken> certificates) {
			this.sharedPool = sharedPool;
			this.certificates = certificates;
		}

		@Override
		public Integer call() throws Exception {

			for (CertificateToken certificateToken : certificates) {
				for (CertificateSourceType source : CertificateSourceType.values()) {
					sharedPool.getInstance(certificateToken, source);
				}
			}

			for (CertificateToken certificateToken : certificates) {
				assertTrue("Certificate should be trusted", sharedPool.isTrusted(certificateToken));
				assertFalse("Sources for certificate shouldn't be empty", sharedPool.getSources(certificateToken).isEmpty());
				assertFalse("Certificate by subject shoudln't be empty", sharedPool.get(certificateToken.getSubjectX500Principal()).isEmpty());
			}

			return sharedPool.getNumberOfCertificates();
		}

	}

}
