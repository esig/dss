package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class GetOriginalDocumentTest extends PKIFactoryAccess {

	private static final Logger LOG = LoggerFactory.getLogger(GetOriginalDocumentTest.class);

	// TODO. (Re-enable when fixed: https://esig-dss.atlassian.net/browse/DSS-969)
	@Ignore
	@Test
	public final void getOriginalDocumentFromEnvelopedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.pdf");

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());

		assertEquals(1, results.size());

		LOG.info("ORIGINAL : \n" + Utils.toBase64(DSSUtils.toByteArray(signedDocument)));
		LOG.info("RETRIEVED : \n" + Utils.toBase64(DSSUtils.toByteArray(results.get(0))));

		assertEquals(document.getDigest(DigestAlgorithm.SHA256), results.get(0).getDigest(DigestAlgorithm.SHA256));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
