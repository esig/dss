package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class JAdESDoubleSignatureDifferentEtsiUTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/jades-double-sig-different-etsiU.json");
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		assertEquals(2, diagnosticData.getSignatures().size());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);

		boolean ltSignatureFound = false;
		boolean ltaSignatureFound = false;
		for (String signatureId : diagnosticData.getSignatureIdList()) {
			if (SignatureLevel.JAdES_BASELINE_LT.equals(diagnosticData.getSignatureFormat(signatureId))) {
				ltSignatureFound = true;
			} else if (SignatureLevel.JAdES_BASELINE_LTA.equals(diagnosticData.getSignatureFormat(signatureId))) {
				ltaSignatureFound = true;
			}
		}
		assertTrue(ltSignatureFound);
		assertTrue(ltaSignatureFound);
	}

}
