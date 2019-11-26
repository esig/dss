package eu.europa.esig.dss.asic.cades.extension.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class ASiCeTimestampingTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {
		
		// TODO : implement the extension support
		DSSException exception = assertThrows(DSSException.class, () -> {
			DSSDocument doc = new FileDocument("src/test/resources/signable/no-signature-container.sce");
			
			ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
			service.setTspSource(getGoodTsa());
			ASiCWithCAdESSignatureParameters extendParams = new ASiCWithCAdESSignatureParameters();
			
			extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
			extendParams.setSigningCertificate(getSigningCert());
			extendParams.aSiC().setContainerType(ASiCContainerType.ASiC_E);
			service.extendDocument(doc, extendParams);
		});
		assertEquals("Unsupported file type", exception.getMessage());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
