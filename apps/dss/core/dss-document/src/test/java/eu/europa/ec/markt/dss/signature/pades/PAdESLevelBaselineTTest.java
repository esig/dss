package eu.europa.ec.markt.dss.signature.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Date;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockTSPSource;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class PAdESLevelBaselineTTest {

	private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	private static DSSDocument toBeSigned;

	private static DSSPrivateKeyEntry privateKeyEntry;
	private static DSSPrivateKeyEntry tspPrivateKeyEntry;

	@BeforeClass
	public static void setUp() throws Exception {
		toBeSigned = new FileDocument(new File("src/test/resources/sample.pdf"));
		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);
		tspPrivateKeyEntry = certificateService.generateTspCertificate(signatureAlgorithm);
	}

	@Test
	public void testSignAndValidate() throws Exception {

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		PAdESService service = new PAdESService(verifier);
		service.setTspSource(new MockTSPSource(tspPrivateKeyEntry, new Date()));

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.setCertificateChain(privateKeyEntry.getCertificateChain());

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		assertTrue(signedDocument.getName().endsWith(".pdf"));
		assertTrue(MimeType.PDF.equals(signedDocument.getMimeType()));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertEquals(SignatureLevel.PAdES_BASELINE_T.name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
