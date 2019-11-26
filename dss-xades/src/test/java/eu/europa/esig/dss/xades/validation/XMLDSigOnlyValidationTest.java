package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XMLDSigOnlyValidationTest {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xmldsig-only.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		validator.setCertificateVerifier(commonCertificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatureIdList().size());

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isSignatureIntact());
		assertTrue(signatureWrapper.isSignatureValid());
		assertFalse(signatureWrapper.isAttributePresent());
		assertFalse(signatureWrapper.isIssuerSerialMatch());
		assertFalse(signatureWrapper.isDigestValuePresent());
		assertFalse(signatureWrapper.isDigestValueMatch());
		assertEquals(SignatureLevel.XML_NOT_ETSI, signatureWrapper.getSignatureFormat());
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			assertTrue(xmlDigestMatcher.isDataFound());
			assertTrue(xmlDigestMatcher.isDataIntact());
		}
	}

}
