package eu.europa.ec.markt.dss.signature.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.BeforeClass;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.utils.TestUtils;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class DoubleSignatureBug {

	private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	private static DSSDocument toBeSigned;

	private static DSSPrivateKeyEntry privateKeyEntry;

	@BeforeClass
	public static void setUp() throws Exception {
		toBeSigned = new FileDocument(new File("src/test/resources/sample.pdf"));
		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);
	}

	// @Test
	public void testDoubleSignature() throws InterruptedException {

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		PAdESService service = new PAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		params.setSigningCertificate(privateKeyEntry.getCertificate());

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = TestUtils.sign(signatureAlgorithm, privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		params.setSigningCertificate(privateKeyEntry.getCertificate());

		Thread.sleep(2000);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = TestUtils.sign(signatureAlgorithm, privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		// Bug with 2 signatures which have the same ID
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}
	}

}
