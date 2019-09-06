package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.junit.jupiter.api.RepeatedTest;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESExtensionWithContentTimestampTest extends PKIFactoryAccess {
	
	@RepeatedTest(10)
	public void test() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		
		Date oneDayBefore = getDateWithHoursDifference(-24);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(oneDayBefore);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		certificateVerifier.setExceptionOnNoRevocationAfterBestSignatureTime(true);
		XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsaByTime(oneDayBefore));
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		signatureParameters.bLevel().setSigningDate(getDateWithHoursDifference(24));
		service.setTspSource(getAlternateGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		Exception exception = assertThrows(DSSException.class, () -> service.extendDocument(signedDocument, signatureParameters));
		assertEquals("Revocation data thisUpdate time is after the bestSignatureTime", exception.getMessage());
		
	}
	
	private Date getDateWithHoursDifference(int hours) {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.HOUR, hours);
		return cal.getTime();
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
