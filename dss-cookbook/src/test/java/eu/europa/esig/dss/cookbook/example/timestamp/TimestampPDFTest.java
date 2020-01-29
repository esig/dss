package eu.europa.esig.dss.cookbook.example.timestamp;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class TimestampPDFTest extends CookbookTools {
	
	@Test
	public void test() throws Exception {

		// tag::creation[]
		// Loads a document to be timestamped
		DSSDocument documentToTimestamp = new FileDocument(new File("src/main/resources/hello-world.pdf"));
		
		// Configure a PAdES service for PDF timestamping
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		// Execute the timestamp method
		DSSDocument timestampedDoc = service.timestamp(documentToTimestamp, new PAdESTimestampParameters());
		// end::creation[]

		// tag::validation[]
		// Load a document validator. The appropriate validator class will be determined automatically.
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(timestampedDoc);
		// Configure the validator. Provide a certificate verifier.
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		// Validate the document
		Reports reports = validator.validateDocument();
		// end::validation[]
		assertNotNull(reports);
		
	}

}
