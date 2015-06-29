package known.issues.DSS650;

import java.io.File;
import java.util.Date;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCSignatureParameters;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.x509.SignatureForm;

public class ASiCeSignAndExtendTest {

	@Test
	public void sign() throws Exception {
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry entry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		ASiCService service = new ASiCService(new CommonCertificateVerifier());

		DSSDocument toSignDocument = new InMemoryDocument("HELLO".getBytes(), "hello.bin");
		ASiCSignatureParameters parameters = new ASiCSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);
		parameters.aSiC().setUnderlyingForm(SignatureForm.CAdES);
		parameters.setSigningCertificate(entry.getCertificate());

		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
		SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, entry, dataToSign);
		DSSDocument signDocument = service.signDocument(toSignDocument, parameters, signatureValue);

		signDocument.save("target/asic-e-cades-b.asice");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

	}

	@Test
	public void extend() throws Exception {
		DSSDocument docToExtend = new FileDocument(new File("target/asic-e-cades-b.asice"));

		ASiCService service = new ASiCService(new CommonCertificateVerifier());
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));

		ASiCSignatureParameters parameters = new ASiCSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_LT);
		parameters.aSiC().setUnderlyingForm(SignatureForm.CAdES);
		DSSDocument extendDocument = service.extendDocument(docToExtend, parameters);
		extendDocument.save("target/extend-asic-e.asice");

	}
}
