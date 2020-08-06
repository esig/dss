package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class XAdESSignedSingleSignaturePropertyTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/signature_property_signed.xml"));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		
		boolean signedPropertiesFound = false;
		boolean signaturePropertiesFound = false;
		boolean referenceFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			switch (digestMatcher.getType()) {
				case SIGNED_PROPERTIES:
					signedPropertiesFound = true;
					break;
				case SIGNATURE_PROPERTIES:
					signaturePropertiesFound = true;
					break;
				case REFERENCE:
					referenceFound = true;
					break;
				default:
					fail("Unexpected DigestMatcherType: " + digestMatcher.getType());
			}
		}
		assertTrue(signedPropertiesFound);
		assertTrue(signaturePropertiesFound);
		assertTrue(referenceFound);
	}

}
