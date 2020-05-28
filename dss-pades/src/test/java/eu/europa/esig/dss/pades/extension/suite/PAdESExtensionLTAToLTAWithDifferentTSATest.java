package eu.europa.esig.dss.pades.extension.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class PAdESExtensionLTAToLTAWithDifferentTSATest extends AbstractPAdESTestExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {

		// Sign
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getSelfSignedTsa());

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument tLevelDoc = service.signDocument(doc, signatureParameters, signatureValue);
		
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		return service.extendDocument(tLevelDoc, signatureParameters);
	}
	
	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsaCrossCertification();
	}
	
	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
		
		// second LTA
		if (allTimestamps.size() > 2) {
			PDFDocumentValidator pdfValidator = (PDFDocumentValidator) validator;
			assertEquals(2, pdfValidator.getDssDictionaries().size());
		}
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
