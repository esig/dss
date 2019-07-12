package eu.europa.esig.dss.xades.signature.prettyprint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class DoubleSignaturePrettyPrintTest extends PKIFactoryAccess {

	@Test
	public void firstOnlySignaturesPrettyPrintTest() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(false);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}

	@Test
	public void secondSignaturePrettyPrintTest() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}

	@Test
	public void bothSignaturesPrettyPrintTest() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}
	
	@Test
	public void doubleSignatureLTALevelTest() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
		
	}
	
	@Test
	public void doubleSignatureMixedLevelTest() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setPrettyPrint(false);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "doubleSignedTestFirst.xml");
		
		validate(signedDocument);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_A);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		params.setEn319132(false);
		params.setPrettyPrint(true);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedTestSecond.xml");

		validate(doubleSignedDocument);

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
		
	}
	
	@Test
	public void doubleCreatedSignatureTest() {
		
		DiagnosticData diagnosticData = validate(new FileDocument("src/test/resources/validation/doubleSignedTest.xml"));
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlRevocationRef> allFoundRevocationRefs = signatureWrapper.getAllFoundRevocationRefs();
		assertNotNull(allFoundRevocationRefs);
		assertEquals(0, allFoundRevocationRefs.size());
		
		assertEquals(1, signatureWrapper.getRelatedRevocations().size());
		assertEquals(1, signatureWrapper.getOrphanRevocations().size());
		
		List<XmlRelatedCertificate> foundCertificatesByLocation = signatureWrapper.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
		assertNotNull(foundCertificatesByLocation);
		assertEquals(2, foundCertificatesByLocation.size());
		
		SignatureWrapper signature2Wrapper = signatures.get(1);
		allFoundRevocationRefs = signature2Wrapper.getAllFoundRevocationRefs();
		assertNotNull(allFoundRevocationRefs);
		assertEquals(2, allFoundRevocationRefs.size());
		assertEquals(2, signature2Wrapper.getRelatedRevocations().size());
		assertEquals(0, signature2Wrapper.getOrphanRevocations().size());
		
	}
	
	private DiagnosticData validate(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}
		return diagnosticData;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
