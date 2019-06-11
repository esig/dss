package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DSS1562Test extends PKIFactoryAccess {
	
	@Test
	public void test() {
		
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-detached-with-object-type-ref.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		DSSDocument detachedContent = new FileDocument("src/test/resources/sample.png");
		validator.setDetachedContents(Arrays.asList(detachedContent));
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertNotNull(signature.getDigestMatchers());
		assertEquals(2, signature.getDigestMatchers().size());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertNotNull(digestMatcher.getType());
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
}
