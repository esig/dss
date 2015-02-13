package eu.europa.ec.markt.dss.signature.cades;

import static org.junit.Assert.assertTrue;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public class CAdESProfileEPESTest {

	protected PrivateKey privateKey;

	protected X509Certificate signingCert;
	protected X509Certificate[] certificateChain;
	protected DSSDocument doc;

	@Before
	public void setUp() throws Exception {

		CertificateService certificateService = new CertificateService();

		DSSPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA1);

		privateKey = privateKeyEntry.getPrivateKey();
		signingCert = privateKeyEntry.getCertificate();
		certificateChain = privateKeyEntry.getCertificateChain();

		doc = new InMemoryDocument("Hello World".getBytes());

	}

	private SignatureParameters buildParameters() {

		SignatureParameters parameters = new SignatureParameters();
		parameters.bLevel().setSigningDate(new Date());
		parameters.setSigningCertificate(signingCert);
		parameters.setCertificateChain(certificateChain);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
		BLevelParameters.Policy policy = new BLevelParameters.Policy();
		policy.setId("");
		parameters.bLevel().setSignaturePolicy(policy);

		return parameters;
	}

	@Test
	public void testCAdESProfile() throws Exception {

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		SignatureParameters parameters = buildParameters();

		final byte[] dataToSign = service.getDataToSign(doc, parameters);
		final byte[] signatureValue = DSSUtils.encrypt(parameters.getSignatureAlgorithm().getJCEId(), privateKey, dataToSign);

		DSSDocument signDocument = service.signDocument(doc, parameters, signatureValue);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signDocument);
		documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = documentValidator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
}
