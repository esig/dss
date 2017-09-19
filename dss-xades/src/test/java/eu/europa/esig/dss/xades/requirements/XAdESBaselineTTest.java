package eu.europa.esig.dss.xades.requirements;

import java.io.File;

import javax.xml.xpath.XPathExpressionException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESBaselineTTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}

	@Override
	public void checkArchiveTimeStampPresent() throws XPathExpressionException {
		// No ArchiveTimestamp in Baseline Profile T
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
