package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESExtensionRevocationFreshnessTest extends PKIFactoryAccess {
	
	private DSSDocument documentToSign;
	private CertificateVerifier certificateVerifier;
	private String signingAlias;
	private XAdESSignatureParameters signatureParameters;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		certificateVerifier = getCompleteCertificateVerifier();
		signingAlias = EE_GOOD_USER;
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
	}
	
	@Test
	public void noExceptionTest() {
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		
		certificateVerifier.setExceptionOnNoRevocationAfterBestSignatureTime(false);
		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getAlternateGoodTsa());

		DSSDocument signedDocument = sign(service, documentToSign);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		
		validate(extendedDocument);
		
	}
	
	@Test
	public void throwExceptionTest() {
		Exception exception = assertThrows(DSSException.class, () -> {
			signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
			
			certificateVerifier.setExceptionOnNoRevocationAfterBestSignatureTime(true);
			XAdESService service = new XAdESService(certificateVerifier);
	        service.setTspSource(getGoodTsa());

			DSSDocument signedDocument = sign(service, documentToSign);
			
			signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
			service.extendDocument(signedDocument, signatureParameters);
		});
		assertEquals("Revocation data thisUpdate time is after the bestSignatureTime", exception.getMessage());
	}
	
	@Test
	public void throwExceptionWithDelayTest() throws Exception {
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		
		certificateVerifier.setExceptionOnNoRevocationAfterBestSignatureTime(true);
		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getAlternateGoodTsa());

		DSSDocument signedDocument = sign(service, documentToSign);
		
		Thread.sleep(1000);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, signatureParameters);
		
		validate(extendedDocument);
		
	}
	
	private DSSDocument sign(XAdESService service, DSSDocument doc) {
		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}
	
	private void validate(DSSDocument doc) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}