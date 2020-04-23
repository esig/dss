package eu.europa.esig.dss.pades.validation.suite.dss818;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class DSS818SKTest extends AbstractDSS818Test {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-SK-1 (HASH_FAILURE).pdf"));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertFalse(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertTrue(timestampWrapper.isSigningCertificateIdentified());
			assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
			assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
			
			CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
			assertNotNull(signingCertificateReference);
			assertTrue(signingCertificateReference.isDigestValuePresent());
			assertTrue(signingCertificateReference.isDigestValueMatch());
			assertFalse(signingCertificateReference.isIssuerSerialPresent());
			assertFalse(signingCertificateReference.isIssuerSerialMatch());
		}
	}

}
