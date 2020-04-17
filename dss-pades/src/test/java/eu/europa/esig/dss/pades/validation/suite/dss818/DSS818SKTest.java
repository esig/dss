package eu.europa.esig.dss.pades.validation.suite.dss818;

import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class DSS818SKTest extends AbstractDSS818Test {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-SK-1 (HASH_FAILURE).pdf"));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isDigestValuePresent());
		assertTrue(signatureWrapper.isDigestValueMatch());
		assertTrue(signatureWrapper.isIssuerSerialMatch());
	}

}
