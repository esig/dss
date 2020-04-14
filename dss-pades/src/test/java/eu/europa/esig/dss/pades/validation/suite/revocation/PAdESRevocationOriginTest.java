package eu.europa.esig.dss.pades.validation.suite.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class PAdESRevocationOriginTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-HU_POL-3.pdf"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
	
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertEquals(3, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(4, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(3, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(4, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
	}

}
