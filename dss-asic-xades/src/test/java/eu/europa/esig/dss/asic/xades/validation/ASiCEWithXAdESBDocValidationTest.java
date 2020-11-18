package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithXAdESBDocValidationTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/hello.bdoc");
	}

	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);

		assertEquals(ASiCContainerType.ASiC_E, diagnosticData.getContainerType());
		assertTrue(diagnosticData.isMimetypeFilePresent());
		assertEquals("application/vnd.bdoc-1.0", diagnosticData.getMimetypeFileContent());
	}

}
