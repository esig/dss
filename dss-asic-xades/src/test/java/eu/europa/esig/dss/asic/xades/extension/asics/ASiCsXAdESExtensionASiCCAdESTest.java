package eu.europa.esig.dss.asic.xades.extension.asics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class ASiCsXAdESExtensionASiCCAdESTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument documentToExtend = new FileDocument("src/test/resources/signable/asic_cades.zip");

		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
		
		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		DSSException exception = assertThrows(DSSException.class, () -> {
			service.extendDocument(documentToExtend, signatureParameters);
		});
		assertEquals("Unsupported file type", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
