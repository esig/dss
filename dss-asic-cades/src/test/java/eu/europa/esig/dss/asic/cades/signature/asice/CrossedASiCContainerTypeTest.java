package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class CrossedASiCContainerTypeTest extends AbstractASiCECAdESTestSignature {

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters> service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		service = new ASiCWithCAdESService(getCompleteCertificateVerifier());

		documentToSign = new FileDocument("src/test/resources/validation/onefile-ok.asice");

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
	}

	@Test
	@Override
	public void signAndVerify() throws IOException {
		UnsupportedOperationException exception = assertThrows(UnsupportedOperationException.class, () -> super.signAndVerify());
		assertEquals("Original container type 'ASiC_E' vs parameter : 'ASiC_S'", exception.getMessage());
	}

	@Override
	protected DocumentSignatureService<ASiCWithCAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
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
