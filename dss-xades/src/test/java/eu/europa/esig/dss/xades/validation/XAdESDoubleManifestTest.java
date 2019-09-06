package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdESDoubleManifestTest {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/SK_DIT/Signature-X-SK_DIT-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(7, digestMatchers.size());
		
		int manifestCounter = 0;
		int manifestEntryCounter = 0;
		List<String> referenceNames = new ArrayList<String>();
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
				manifestCounter++;
			} else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntryCounter++;
			}
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
			assertFalse(referenceNames.contains(digestMatcher.getName()));
			referenceNames.add(digestMatcher.getName());
		}
		assertEquals(2, manifestCounter);
		assertEquals(2, manifestEntryCounter);
		
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(5, signatureScopes.size());
		for (XmlSignatureScope signatureScope : signatureScopes) {
			assertNotNull(signatureScope.getName());
			assertNotNull(signatureScope.getDescription());
			assertNotNull(signatureScope.getSignerData());
			assertNotNull(signatureScope.getScope());
			List<String> transformations = signatureScope.getTransformations();
			assertTrue(Utils.isCollectionNotEmpty(transformations));
		}
		
		List<XmlSignerData> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(5, originalSignerDocuments.size());
		
	}

}
