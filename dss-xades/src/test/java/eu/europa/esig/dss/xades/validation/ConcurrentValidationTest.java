package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Test DSS with multi threads
 * 
 */
public class ConcurrentValidationTest {

	@Test
	public void test() throws InterruptedException, ExecutionException {

		ExecutorService executor = Executors.newFixedThreadPool(20);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		DataLoader dataLoader = new NativeHTTPDataLoader();
		certificateVerifier.setDataLoader(dataLoader);

		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();

		for (int i = 0; i < 200; i++) {
			futures.add(executor.submit(new TestConcurrent(certificateVerifier)));
		}

		for (Future<Boolean> future : futures) {
			assertTrue(future.get());
		}

		executor.shutdown();
	}

	class TestConcurrent implements Callable<Boolean> {

		private final CommonCertificateVerifier certificateVerifier;

		public TestConcurrent(CommonCertificateVerifier certificateVerifier) {
			this.certificateVerifier = certificateVerifier;
		}

		@Override
		public Boolean call() throws Exception {
			DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
			validator.setCertificateVerifier(certificateVerifier);

			return new Boolean(validator.validateDocument() != null);
		}

	}

}
