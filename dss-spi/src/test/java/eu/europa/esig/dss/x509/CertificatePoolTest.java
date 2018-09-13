package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class CertificatePoolTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePoolTest.class);

	private static final int NB_THREADS = 1000;

	private CertificateSource initCertSource() {
		return new CertificateSource() {

			private static final long serialVersionUID = 1L;

			@Override
			public List<CertificateToken> getCertificates() {
				CertificateToken c1 = DSSUtils.loadCertificate(new File("src/test/resources/ecdsa.cer"));
				CertificateToken c2 = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
				CertificateToken c3 = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
				CertificateToken c4 = DSSUtils.loadCertificate(new File("src/test/resources/TSA_BE.cer"));

				// c5 & c6 are different but have the same public key
				CertificateToken c5 = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));
				CertificateToken c6 = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2-signed.crt"));
				return Collections.unmodifiableList(Arrays.asList(c1, c2, c3, c4, c5, c6));
			}

			@Override
			public CertificateSourceType getCertificateSourceType() {
				return CertificateSourceType.OTHER;
			}

			@Override
			public List<CertificateToken> get(X500Principal x500Principal) {
				return null;
			}

			@Override
			public CertificateToken addCertificate(CertificateToken certificate) {
				return null;
			}
		};
	}

	@Test
	public void testMultiThreadImport() {

		CertificateSource sharedCertSource = initCertSource();
		List<CertificateToken> certificates = sharedCertSource.getCertificates();
		LOG.info("Nb certs : " + certificates.size());
		CertificateToken EXPECTED_TOKEN = certificates.get(0);

		CertificatePool sharedPool = new CertificatePool();

		final ExecutorService threadPool = Executors.newFixedThreadPool(NB_THREADS);
		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();

		for (int i = 0; i < NB_THREADS; i++) {
			futures.add(threadPool.submit(new CertPoolMergerRunnable(sharedPool, sharedCertSource)));
		}

		int nbThreads = 0;
		for (Future<Boolean> future : futures) {
			try {
				assertTrue(future.get());
				nbThreads++;
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}
		}

		threadPool.shutdown();

		assertEquals(NB_THREADS, nbThreads);

		final boolean correctNumberEntities = sharedPool.getNumberOfEntities() == 5;
		if (!correctNumberEntities) {
			LOG.warn("Nb entities is not correct : {}", sharedPool.getNumberOfEntities());
		}
		final boolean correctNumberCerts = sharedPool.getNumberOfCertificates() == 6;
		if (!correctNumberCerts) {
			LOG.warn("Nb certs is not correct : {}", sharedPool.getNumberOfCertificates());
		}
		final boolean foundCert = Utils.isCollectionNotEmpty(sharedPool.get(EXPECTED_TOKEN.getSubjectX500Principal()));
		assertTrue(correctNumberEntities && correctNumberCerts && foundCert);
	}

	private class CertPoolMergerRunnable implements Callable<Boolean> {

		private final CertificatePool sharedPool;
		private final CertificateSource sharedCertSource;

		public CertPoolMergerRunnable(CertificatePool sharedPool, CertificateSource sharedCertSource) {
			this.sharedPool = sharedPool;
			this.sharedCertSource =sharedCertSource;
		}

		@Override
		public Boolean call() throws Exception {
			sharedPool.importCerts(initCertSource());
			sharedPool.importCerts(sharedCertSource);

			List<CertificateToken> certificateTokens = sharedPool.getCertificateTokens();
			return !certificateTokens.isEmpty();
		}

	}

}
