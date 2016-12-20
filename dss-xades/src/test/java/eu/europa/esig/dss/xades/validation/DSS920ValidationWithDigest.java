package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class DSS920ValidationWithDigest {

	@Test
	public void testValidationWithDigest() throws Exception {

		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.DETACHED);
		params.setSigningCertificate(privateKeyEntry.getCertificate());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = TestUtils.sign(signatureAlgorithm, privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		// PROVIDE WRONG DIGEST WITH WRONG ALGO

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		// Provide only the digest value
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		DigestDocument digestDocument = new DigestDocument();
		digestDocument.setName("sample.xml");
		digestDocument.addDigest(DigestAlgorithm.SHA1, toBeSigned.getDigest(DigestAlgorithm.SHA1));
		detachedContents.add(digestDocument);
		validator.setDetachedContents(detachedContents);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureById.isBLevelTechnicallyValid());

		// PROVIDE CORRECT DIGEST WITH CORRECT ALGO

		validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		// Provide only the digest value
		detachedContents = new ArrayList<DSSDocument>();
		digestDocument = new DigestDocument();
		digestDocument.setName("sample.xml");
		digestDocument.addDigest(DigestAlgorithm.SHA256, toBeSigned.getDigest(DigestAlgorithm.SHA256));
		detachedContents.add(digestDocument);
		validator.setDetachedContents(detachedContents);

		reports = validator.validateDocument();

		diagnosticData = reports.getDiagnosticData();
		signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureById.isBLevelTechnicallyValid());

	}
}
