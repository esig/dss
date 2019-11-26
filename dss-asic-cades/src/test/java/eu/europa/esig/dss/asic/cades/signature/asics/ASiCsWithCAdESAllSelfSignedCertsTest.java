package eu.europa.esig.dss.asic.cades.signature.asics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class ASiCsWithCAdESAllSelfSignedCertsTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private ASiCWithCAdESSignatureParameters parameters;
	private ASiCWithCAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument("Hello World!".getBytes());
		
		parameters = new ASiCWithCAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	public void bLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void tLevelTest() {
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
        DSSDocument signedDocument = sign();
        assertNotNull(signedDocument);
	}

	@Test
	public void ltLevelTest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
	        sign();
		});
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void ltaLevelTest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
	        sign();
		});
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}
	
	private DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, parameters, signatureValue);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
