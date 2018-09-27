package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.fail;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;

public class PAdESLevelBNotEnoughSpaceForSignature extends PKIFactoryAccess {

	@Test
	public void testException() throws Exception {
		DSSDocument toBeSigned = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setSignatureSize(2); // 2 bytes

		DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(getCompleteCertificateVerifier());

		try {
			ToBeSigned dataToSign = service.getDataToSign(toBeSigned, signatureParameters);
			SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
			service.signDocument(toBeSigned, signatureParameters, signatureValue);
			fail("Not enough space");
		} catch (DSSException e) {
			// assertTrue(ExceptionUtils.getStackTrace(e).contains("not enough space"));
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}