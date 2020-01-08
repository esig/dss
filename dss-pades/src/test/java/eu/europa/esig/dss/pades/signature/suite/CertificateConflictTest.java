package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CertificateConflictTest {

	private final PasswordProtection passwordProtection = new PasswordProtection("1qaz@WSX".toCharArray());

	@Test
	public void testPadesCaDuplicate() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);
		DSSDocument signedDocument = padesSign(doc);
		assertEquals(MimeType.PDF, signedDocument.getMimeType());
		padesVerifyPreviousKeystore(signedDocument);
		padesVerifyCurrentKeystore(signedDocument);
	}

	private DSSDocument padesSign(DSSDocument document) {
		InputStream pkcs12Stream = getClass().getResourceAsStream("/cert-conflict/previousKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(pkcs12Stream, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		parameters.setSigningCertificate(privateKey.getCertificate());
		parameters.setCertificateChain(privateKey.getCertificateChain());

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		PAdESService padesService = new PAdESService(verifier);
		ToBeSigned dataToSign = padesService.getDataToSign(document, parameters);

		DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		SignatureValue signatureValue = signatureToken.sign(dataToSign, digestAlgorithm, privateKey);
		return padesService.signDocument(document, parameters, signatureValue);
	}

	private void padesVerifyPreviousKeystore(DSSDocument signedDocument) {
		InputStream pkcs12Stream = getClass().getResourceAsStream("/cert-conflict/previousKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(pkcs12Stream, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		CertificateVerifier cv = new CommonCertificateVerifier();

		CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
		for (CertificateToken cert : privateKey.getCertificateChain()) {
			certificateSource.addCertificate(cert);
		}
		cv.setTrustedCertSource(certificateSource);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);
		documentValidator.setCertificateVerifier(cv);
		Reports reports = documentValidator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getSignatureIdList().size());
		String signatureId = simpleReport.getSignatureIdList().get(0);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
	}

	private void padesVerifyCurrentKeystore(DSSDocument signedDocument) {
		InputStream pkcs12Stream = getClass().getResourceAsStream("/cert-conflict/currentKeystore.pfx");
		Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(pkcs12Stream, passwordProtection);
		DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);

		CertificateVerifier cv = new CommonCertificateVerifier();

		CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
		for (CertificateToken cert : privateKey.getCertificateChain()) {
			certificateSource.addCertificate(cert);
		}
		cv.setTrustedCertSource(certificateSource);

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);
		documentValidator.setCertificateVerifier(cv);
		Reports reports = documentValidator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(1, simpleReport.getSignatureIdList().size());
		String signatureId = simpleReport.getSignatureIdList().get(0);
		assertNotEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
		assertNotEquals(Indication.PASSED, simpleReport.getIndication(signatureId));
	}

}
