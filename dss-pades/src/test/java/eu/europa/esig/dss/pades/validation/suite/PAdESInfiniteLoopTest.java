package eu.europa.esig.dss.pades.validation.suite;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

// See DSS-1872
public class PAdESInfiniteLoopTest {
	
	@Test
	public void test() {
		assertTimeoutPreemptively(ofMillis(3000), () -> {
			DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_infinite_loop.pdf"));
	
			PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
			validator.setCertificateVerifier(new CommonCertificateVerifier());
			Reports reports = validator.validateDocument();
			assertNotNull(reports);
			// NOTE: OpenPDF and PDFBox search for signatures in opposite directions, therefore the results are different!
		});
	}
	
	@Test
	public void oppositeLoopTest() {
		assertTimeoutPreemptively(ofMillis(3000), () -> {
			DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_opposite_infinite_loop.pdf"));
	
			PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
			validator.setCertificateVerifier(new CommonCertificateVerifier());
			Reports reports = validator.validateDocument();
			assertNotNull(reports);
			// NOTE: OpenPDF and PDFBox search for signatures in opposite directions, therefore the results are different!
		});
	}
	
}
