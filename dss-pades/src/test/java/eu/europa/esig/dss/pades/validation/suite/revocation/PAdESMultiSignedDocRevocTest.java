package eu.europa.esig.dss.pades.validation.suite.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class PAdESMultiSignedDocRevocTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-SK-6.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		assertEquals(2, signatures.size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		
		SignatureWrapper signatureOne = signatures.get(0);
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationData().size());
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals("Signature1", signatureOne.getFirstFieldName());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		assertEquals(2, signatureTwo.foundRevocations().getRelatedRevocationData().size());
		assertEquals(2, signatureTwo.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());

		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signatureTwo.foundRevocations().getOrphanRevocationRefs().size());
		assertEquals("Signature3", signatureTwo.getFirstFieldName());
		
		List<TimestampWrapper> timestamps= diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(2, timestamps.size()); // one timestamp is skipped because of /Type /Sig (see DSS-1899)
		
		assertEquals(5, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(0).getType());
		assertEquals(5, timestamps.get(1).getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(1).getType());
	}

}
