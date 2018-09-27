package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class EmbeddedNotXmlSignatureExceptionTest extends AbstractXAdESTestSignature {

	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.png"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEmbedXML(true);
	}

	@Override
	@Test(expected = DSSException.class)
	public void signAndVerify() throws IOException {
		super.signAndVerify(); // enveloping signature with embedded content only allow XML
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
