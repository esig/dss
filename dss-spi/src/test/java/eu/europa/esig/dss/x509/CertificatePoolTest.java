package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.security.auth.x500.X500Principal;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class CertificatePoolTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificatePoolTest.class);

	private static CertificateSource CERT_SOURCE;
	private static CertificateToken EXPECTED_TOKEN;
	private static final int NB_THREADS = 1000;

	@BeforeClass
	public static void init() {

		CERT_SOURCE = new CertificateSource() {

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
				return Arrays.asList(c1, c2, c3, c4, c5, c6);
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
		List<CertificateToken> certificates = CERT_SOURCE.getCertificates();
		LOG.info("Nb certs : " + certificates.size());
		EXPECTED_TOKEN = certificates.get(0);
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
					pool.importCerts(CERT_SOURCE);
					pool.importCerts(CERT_SOURCE);
					final boolean correctNumberEntities = pool.getNumberOfEntities() == 5;
					if (!correctNumberEntities) {
						LOG.warn("Nb entities is not correct : {}", pool.getNumberOfEntities());
					}
					final boolean correctNumberCerts = pool.getNumberOfCertificates() == 6;
					if (!correctNumberCerts) {
						LOG.warn("Nb certs is not correct : {}", pool.getNumberOfCertificates());
					}
					final boolean foundCert = Utils.isCollectionNotEmpty(pool.get(EXPECTED_TOKEN.getSubjectX500Principal()));
					return correctNumberEntities && correctNumberCerts && foundCert;
				}

			}));
		}

		for (Future<Boolean> future : futures) {
			assertTrue(future.get());
		}
	}

}
