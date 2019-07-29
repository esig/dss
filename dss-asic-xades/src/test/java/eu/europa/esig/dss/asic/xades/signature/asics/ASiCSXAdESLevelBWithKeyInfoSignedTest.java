package eu.europa.esig.dss.asic.xades.signature.asics;

import java.util.Date;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class ASiCSXAdESLevelBWithKeyInfoSignedTest extends AbstractASiCSXAdESTestSignature {

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		// DSS-1548
		signatureParameters.setSignKeyInfo(true);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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
