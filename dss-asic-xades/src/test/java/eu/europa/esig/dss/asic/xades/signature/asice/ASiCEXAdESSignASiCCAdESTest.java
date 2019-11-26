package eu.europa.esig.dss.asic.xades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class ASiCEXAdESSignASiCCAdESTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument documentToSign = new FileDocument("src/test/resources/signable/asic_cades.zip");

		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		UnsupportedOperationException exception = assertThrows(UnsupportedOperationException.class, () -> {
			service.getDataToSign(documentToSign, signatureParameters);
		});
		assertEquals("Container type doesn't match", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
