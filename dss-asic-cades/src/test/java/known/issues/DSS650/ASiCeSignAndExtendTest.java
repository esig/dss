package known.issues.DSS650;

import java.io.File;
import java.util.Date;

import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockTSPSource;
import eu.europa.ec.markt.dss.parameter.ASiCWithCAdESSignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.asic.ASiCWithCAdESService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.utils.TestUtils;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class ASiCeSignAndExtendTest {

	@Test
	public void sign() throws Exception {
		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry entry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		ASiCWithCAdESService service = new ASiCWithCAdESService(new CommonCertificateVerifier());

		DSSDocument toSignDocument = new InMemoryDocument("HELLO".getBytes(), "hello.bin");
		ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);
		parameters.setSigningCertificate(entry.getCertificate());

		byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);
		byte[] signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, entry.getPrivateKey(), dataToSign);
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

		ASiCWithCAdESService service = new ASiCWithCAdESService(new CommonCertificateVerifier());
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));

		ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_LT);
		DSSDocument extendDocument = service.extendDocument(docToExtend, parameters);
		extendDocument.save("target/extend-asic-e.asice");
	}
}
