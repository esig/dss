package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class XAdESWithPolicyValidationTest extends AbstractXAdESTestValidation {

	private static final String POLICY_ID = "1.3.6.1.4.1.10015.1000.3.2.1";
	private static final String POLICY_URL = "http://spuri.test";

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/valid-xades.xml");
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(POLICY_ID, signature.getPolicyId());
		assertEquals(POLICY_URL, signature.getPolicyUrl());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// do nothing
	}

}
