package eu.europa.esig.dss.xades.signature.prettyprint;

import java.util.Date;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class SignSignatureWithTimestampTest {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
/*
	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/ES/Signature-X-ES-103.xml");
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setPrettyPrint(true);
		
		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}*/

}
