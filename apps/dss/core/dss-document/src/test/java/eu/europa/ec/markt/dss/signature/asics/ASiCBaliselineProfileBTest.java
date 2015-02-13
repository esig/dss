package eu.europa.ec.markt.dss.signature.asics;

import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockEmptyTSLCertificateSource;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class ASiCBaliselineProfileBTest {

	private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	private static DSSDocument toBeSigned;

	private static DSSPrivateKeyEntry privateKeyEntry;

	@BeforeClass
	public static void setUp() throws Exception {
		toBeSigned = new InMemoryDocument("Hello Wolrd !".getBytes(), "document.pdf");
		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);
	}

	@Test
	public void testSignAndValidate() {
		final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(new MockEmptyTSLCertificateSource());

		final ASiCService service = new ASiCService(certificateVerifier);

		final SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_B);
		params.setSigningCertificate(privateKeyEntry.getCertificate());

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		assertTrue(signedDocument.getName().endsWith(".asics"));
		assertTrue(MimeType.ASICS.equals(signedDocument.getMimeType()));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

	}

}
