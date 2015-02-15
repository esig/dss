package eu.europa.ec.markt.dss.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.pdfbox.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

public abstract class AbstractTestSignature {

	private static final Logger LOGGER = LoggerFactory.getLogger(AbstractTestSignature.class);

	protected abstract DSSDocument getDocumentToSign();

	protected abstract DocumentSignatureService getService();

	protected abstract DSSPrivateKeyEntry getPrivateKeyEntry();

	protected abstract SignatureParameters getSignatureParameters();

	protected abstract MimeType getExpectedMime();

	protected abstract boolean isBaselineT();

	protected abstract boolean isBaselineLTA();

	@Test
	public void signAndVerify() {
		final DSSDocument signedDocument = sign();

		try {
			IOUtils.copy(signedDocument.openStream(), System.out);
		} catch (Exception e) {
			LOGGER.error("Cannot display file content", e);
		}

		checkMimeType(signedDocument);

		Reports reports = getValidationReport(signedDocument);

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		checkNumberOfSignatures(diagnosticData);
		checkDigestAlgorithm(getSignatureParameters().getDigestAlgorithm(), diagnosticData);
		checkEncryptionAlgorithm(getSignatureParameters().getEncryptionAlgorithm(), diagnosticData);
		checkSigningCertificateValue(diagnosticData);
		checkIssuerSigningCertificateValue(diagnosticData);
		checkCertificateChain(diagnosticData);
		checkSignatureLevel(getSignatureParameters().getSignatureLevel(), diagnosticData);
		checkBLevelValid(diagnosticData);
		checkTLevelAndValid(diagnosticData);
		checkALevelAndValid(diagnosticData);

	}

	protected DSSDocument sign() {
		DSSDocument toBeSigned = getDocumentToSign();
		SignatureParameters params = getSignatureParameters();
		DocumentSignatureService service = getService();
		DSSPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();

		final byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		final byte[] signatureValue = DSSUtils.encrypt(params.getSignatureAlgorithm().getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		final DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		return signedDocument;
	}

	protected Reports getValidationReport(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		return reports;
	}

	protected void checkMimeType(DSSDocument signedDocument) {
		assertEquals(getExpectedMime(), signedDocument.getMimeType());
	}

	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(1, (diagnosticData.getSignatureIdList() == null ? 0 : diagnosticData.getSignatureIdList().size()));
	}

	protected void checkDigestAlgorithm(DigestAlgorithm digestAlgorithm, DiagnosticData diagnosticData) {
		assertEquals(digestAlgorithm, diagnosticData.getSignatureDigestAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	private void checkEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm, DiagnosticData diagnosticData) {
		assertEquals(encryptionAlgorithm, diagnosticData.getSignatureEncryptionAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		int signingCertificateId = diagnosticData.getSigningCertificateId();
		String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
		String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
		X509Certificate certificate = getPrivateKeyEntry().getCertificate();
		// Remove space, normal ?
		assertEquals(certificate.getSubjectDN().getName().replace(" ", ""), certificateDN.replace(" ", ""));
		assertEquals(certificate.getSerialNumber().toString(), certificateSerialNumber);
	}

	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		int signingCertificateId = diagnosticData.getSigningCertificateId();
		String issuerDN = diagnosticData.getCertificateIssuerDN(signingCertificateId);
		X509Certificate certificate = getPrivateKeyEntry().getCertificate();
		// Remove space, normal ?
		assertEquals(certificate.getIssuerDN().getName().replace(" ", ""), issuerDN.replace(" ", ""));
	}

	private void checkCertificateChain(DiagnosticData diagnosticData) {
		DSSPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();
		List<Integer> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		// TODO what is correct ? signing certificate is in the chain or only
		// parents ?
		assertEquals(privateKeyEntry.getCertificateChain().length, signatureCertificateChain.size() - 1);
	}

	protected void checkSignatureLevel(SignatureLevel expectedSignatureLevel, DiagnosticData diagnosticData) {
		assertEquals(expectedSignatureLevel.name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineT(), diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineT(), diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkALevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineLTA(), diagnosticData.isThereALevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineLTA(), diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
}
