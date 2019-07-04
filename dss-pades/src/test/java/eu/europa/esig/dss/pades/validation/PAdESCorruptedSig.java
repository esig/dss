package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class PAdESCorruptedSig extends PKIFactoryAccess {

	@Test
	public void originalPAdESTest() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-original.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSignatureIntact());
	}
	
	@Test
	public void corruptedPAdESTest() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-corrupted.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSignatureIntact());
	}
	
	@Test
	public void outOfByteRangePAdESTest() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-out-of-byteRange.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSignatureIntact());
	}
	
	@Override
	protected String getSigningAlias() {
		return null;
	}

}
