package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESExtensionAllSelfSignedCertsTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private XAdESSignatureParameters parameters;
	private XAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument("src/test/resources/sample.xml");
		
		parameters = new XAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	public void bToTTest() {
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        DSSDocument signedDocument = sign();
        
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		DSSDocument extendedDocument = extend(signedDocument);
		assertNotNull(extendedDocument);
	}

	@Test
	public void bToLTTest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
	        DSSDocument signedDocument = sign();
	        
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
			extend(signedDocument);
		});
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void tToLTTest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
	        DSSDocument signedDocument = sign();
	        
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
			extend(signedDocument);
		});
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}

	@Test
	public void tToLTATest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
	        DSSDocument signedDocument = sign();
	        
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
			extend(signedDocument);
		});
		assertEquals("Cannot extend the signature. The signature contains only self-signed certificate chains!", exception.getMessage());
	}
	
	private DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        return service.signDocument(documentToSign, parameters, signatureValue);
	}
	
	private DSSDocument extend(DSSDocument document) {
		return service.extendDocument(document, parameters);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
