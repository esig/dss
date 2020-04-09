package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESSignatureScopeTest extends PKIFactoryAccess {
	
	@Test
	public void envelopingTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-2011/cades-enveloping.pkcs7");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
				assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
				assertTrue(Arrays.equals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue()));
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
		
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
		assertEquals(originalDocuments.get(0).getDigest(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod()), 
				Utils.toBase64(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue()));
	}
	
	@Test
	public void brokenEnvelopingTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-2011/cades-enveloping-broken.pkcs7");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
				assertTrue(Arrays.equals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue()));
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
		
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
		assertNotEquals(originalDocuments.get(0).getDigest(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod()), 
				Utils.toBase64(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue()));
	}
	
	@Test
	public void detachedTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-2011/cades-detached.pkcs7");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(new InMemoryDocument("Hello World".getBytes())));
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
				assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
				assertTrue(Arrays.equals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue()));
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
		
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
		assertEquals(originalDocuments.get(0).getDigest(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod()), 
				Utils.toBase64(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue()));
	}
	
	@Test
	public void wrongDetachedFileProvidedTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-2011/cades-detached.pkcs7");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(new InMemoryDocument("Bye World".getBytes())));
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
				assertTrue(Arrays.equals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue()));
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
		
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
		assertNotEquals(originalDocuments.get(0).getDigest(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod()), 
				Utils.toBase64(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue()));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
