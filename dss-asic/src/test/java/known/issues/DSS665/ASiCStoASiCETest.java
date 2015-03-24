package known.issues.DSS665;

import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.parameter.ASiCSignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.utils.TestUtils;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class ASiCStoASiCETest {

	@Test
	public void test() throws Exception{
		DSSDocument documentToSign = new InMemoryDocument("Hello Wolrd !".getBytes(), "test.text");

		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry	privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		ASiCSignatureParameters signatureParameters = new ASiCSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		ASiCService service = new ASiCService(certificateVerifier);

		byte[] dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		byte[] signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);

		certificateVerifier = new CommonCertificateVerifier();
		service = new ASiCService(certificateVerifier);

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

	}

}
