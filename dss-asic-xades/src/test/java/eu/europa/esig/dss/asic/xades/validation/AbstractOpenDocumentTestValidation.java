package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractOpenDocumentTestValidation extends AbstractASiCWithXAdESTestValidation {
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);

		assertTrue(areManifestAndMimetypeCovered(diagnosticData));
	}
	
	private boolean areManifestAndMimetypeCovered(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		boolean isManifestCovered = false;
		boolean isMimetypeCovered = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (digestMatcher.getName().contains("manifest.xml")) {
				isManifestCovered = true;
			} else if (digestMatcher.getName().contains("mimetype")) {
				isMimetypeCovered = true;
			}
		}
		return isManifestCovered && isMimetypeCovered;
	}
	
//	@Override
//	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
//		for (AdvancedSignature advancedSignature : validator.getSignatures()) {
//			assertTrue(Utils.isCollectionEmpty(validator.getOriginalDocuments(advancedSignature)));
//		}
//	}

}
