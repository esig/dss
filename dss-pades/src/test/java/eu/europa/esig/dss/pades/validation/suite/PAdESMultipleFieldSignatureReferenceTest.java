package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.reports.Reports;

/* See DSS-1895 */
public class PAdESMultipleFieldSignatureReferenceTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/signature-referenced-from-multiple-fields.pdf"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		List<String> signatureFieldNames = signatures.get(0).getSignatureFieldNames();
		assertEquals(2, signatureFieldNames.size());
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
