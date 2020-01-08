package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESDetachedWithCounterSigTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1892/detached_with_counter_sig.p7m");
		DSSDocument detachedDocument = new FileDocument("src/test/resources/validation/dss-1892/signed_content.bin");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(detachedDocument));
		
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		boolean counterSigFound = false;
		for (SignatureWrapper signature : signatures) {
			assertTrue(signature.isSignatureIntact());
			assertTrue(signature.isSignatureValid());
			if (signature.isCounterSignature()) {
				counterSigFound = true;
			}
			assertEquals(1, signature.getTimestampList().size());
		}
		assertTrue(counterSigFound);
		
		assertEquals(2, diagnosticData.getTimestampList().size());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
