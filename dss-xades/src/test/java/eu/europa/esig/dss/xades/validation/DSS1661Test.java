package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1661Test extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-with-no-name-reference.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertNotNull(signature.getDigestMatchers());
		assertEquals(2, signature.getDigestMatchers().size());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertNotNull(digestMatcher.getType());
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			}
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
	
