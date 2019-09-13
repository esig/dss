package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1770Test {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		assertEquals("Full XML File", xmlSignatureScope.getName());
	}
	
	@Test
	public void rootAndRefsCoveredEnvelopedSigTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770rootAndRefs.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(3, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				assertEquals("Full XML File", signatureScope.getName()); // the whole current file is covered
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(1, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void detachedContentTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770rootAndRefs.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(new FileDocument("src/test/resources/sample.png")));
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(3, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				assertEquals("Full XML File", signatureScope.getName());
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(1, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void detachedContentWithEmptyNameTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770rootAndRefs.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		FileDocument fileDocument = new FileDocument("src/test/resources/sample.png");
		fileDocument.setName("");
		validator.setDetachedContents(Arrays.asList(fileDocument));
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(3, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				assertEquals("Full XML File", signatureScope.getName());
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(1, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void refUriRemovedTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770refUriRemoved.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(2, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(0, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void nullUriWithDetachedContentTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770refUriRemoved.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		FileDocument detachedDocument = new FileDocument("src/test/resources/sample.png");
		validator.setDetachedContents(Arrays.asList(detachedDocument));
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(3, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				assertEquals(detachedDocument.getName(), signatureScope.getName());
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(1, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void nullUriWithMultipleDetachedContentTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770refUriRemoved.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<DSSDocument> detachedDocuments = new ArrayList<DSSDocument>();
		detachedDocuments.add(new FileDocument("src/test/resources/sample.png"));
		detachedDocuments.add(new FileDocument("src/test/resources/sample.xml"));
		validator.setDetachedContents(detachedDocuments);
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(2, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(0, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Test
	public void nullUriWithDetachedContentNullNameTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1770/dss1770refUriRemoved.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(new InMemoryDocument(new byte[] {1, 2, 3})));
		
		Reports reports = validator.validateDocument();
		// reports.print();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(3, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				assertNull(signatureScope.getName());
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(1, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	

}
