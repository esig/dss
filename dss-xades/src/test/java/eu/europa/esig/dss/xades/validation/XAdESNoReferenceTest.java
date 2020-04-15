package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

public class XAdESNoReferenceTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-signed-altered-refRemoved.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		XmlDigestMatcher signedPropertiesDigest = null;
		XmlDigestMatcher refDigest = null;

		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.SIGNED_PROPERTIES == xmlDigestMatcher.getType()) {
				signedPropertiesDigest = xmlDigestMatcher;
			} else if (DigestMatcherType.REFERENCE == xmlDigestMatcher.getType()) {
				refDigest = xmlDigestMatcher;
			} else {
				fail("Unexpected " + xmlDigestMatcher.getType());
			}
		}

		assertNotNull(signedPropertiesDigest);
		assertTrue(signedPropertiesDigest.isDataFound());
		assertTrue(signedPropertiesDigest.isDataIntact());
		assertNotNull(refDigest);
		assertFalse(refDigest.isDataFound());
		assertFalse(refDigest.isDataIntact());
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertTrue(Utils.isCollectionEmpty(originalSignerDocuments));
	}
	
	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		// signed data reference is not present
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);

		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND,
				detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Override
	protected void validateETSISignerDocuments(List<SignersDocumentType> signersDocuments) {
		assertTrue(Utils.isCollectionEmpty(signersDocuments));
	}

}
