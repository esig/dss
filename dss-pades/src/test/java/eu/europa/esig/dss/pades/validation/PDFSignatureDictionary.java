package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class PDFSignatureDictionary {

	@Test
	public void test() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		assertNotNull(signatures);
		for (SignatureWrapper signature : signatures) {
			List<BigInteger> byteRange = signature.getSignatureByteRange();
			assertNotNull(byteRange);
			assertEquals(4, byteRange.size());
			assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
		}
		
	}
	
}
