package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class XAdESSignedPropertiesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-signed.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
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
		assertTrue(refDigest.isDataFound());
		assertTrue(refDigest.isDataIntact());
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);

		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND,
				detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
	}

}
