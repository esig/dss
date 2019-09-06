package eu.europa.esig.dss.asic.xades.signature.asice;

import java.util.Date;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class AsiCEXAdESLevelLTAWithKeyInfoTest extends AbstractASiCEXAdESTestSignature {

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		// DSS-1548
		signatureParameters.setSignKeyInfo(true);
		signatureParameters.setKeyInfoCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
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
