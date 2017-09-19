package eu.europa.esig.dss.xades.validation;

import java.io.File;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESBExtendToLTACheckTimeStampIDTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned toBeSigned = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(toBeSigned, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		signedDocument = service.extendDocument(signedDocument, signatureParameters);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnostic = report.getDiagnosticData();
		String signatureId = diagnostic.getFirstSignatureId();
		for (TimestampWrapper wrapper : diagnostic.getTimestampList(signatureId)) {
			Assert.assertEquals(signatureId, wrapper.getSignedObjects().getSignedSignature().get(0).getId());
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
