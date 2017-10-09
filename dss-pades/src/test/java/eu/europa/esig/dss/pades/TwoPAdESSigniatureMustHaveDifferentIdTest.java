package eu.europa.esig.dss.pades;

import java.io.File;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class TwoPAdESSigniatureMustHaveDifferentIdTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.pdf"));

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setLocation("Luxembourg");
		signatureParameters.setReason("DSS testing");
		signatureParameters.setContactInfo("Jira");

		DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument firstSignedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(firstSignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		signatureParameters.bLevel().setSigningDate(new Date());

		dataToSign = service.getDataToSign(firstSignedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument secondSignedDocument = service.signDocument(firstSignedDocument, signatureParameters, signatureValue);

		validator = SignedDocumentValidator.fromDocument(secondSignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		reports = validator.validateDocument();

		List<String> signatureIdList = reports.getSimpleReport().getSignatureIdList();

		Assert.assertEquals(2, new HashSet<String>(reports.getSimpleReport().getSignatureIdList()).size());
		Assert.assertNotEquals(signatureIdList.get(0), signatureIdList.get(1));

	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
