package eu.europa.esig.dss.pades.validation.suite.dss917;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;

public class DSS917Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/hello_signed_INCSAVE_signed.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);

		List<SignatureWrapper> allSignatures = diagnosticData.getSignatures();
		assertEquals(2, allSignatures.size());
	}

}
