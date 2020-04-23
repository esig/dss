package eu.europa.esig.dss.cades.validation.dss1401;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class DSS916QesAttachedTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-916/test.txt.signed.qes.attached.p7s");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		// TODO Auto-generated method stub
		super.checkTimestamps(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> timestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		assertEquals(1, timestamps.size());
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
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(SignatureLevel.CAdES_101733_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
