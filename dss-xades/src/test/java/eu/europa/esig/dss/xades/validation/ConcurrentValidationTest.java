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

		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();

		for (int i = 0; i < 20; i++) {
			futures.add(executor.submit(new TestConcurrent()));
		}

		for (Future<Boolean> future : futures) {
			assertTrue(future.get());
		}

		executor.shutdown();
	}

	class TestConcurrent implements Callable<Boolean> {

		@Override
		public Boolean call() throws Exception {
			DSSDocument doc = new FileDocument("src/test/resources/dss-817-test.xml");
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
			validator.setCertificateVerifier(new CommonCertificateVerifier());

			return new Boolean(validator.validateDocument() != null);
		}

	}

}
