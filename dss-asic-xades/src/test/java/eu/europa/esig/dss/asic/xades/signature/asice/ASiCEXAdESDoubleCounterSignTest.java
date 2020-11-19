package eu.europa.esig.dss.asic.xades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCXAdESCounterSignatureTest;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;

public class ASiCEXAdESDoubleCounterSignTest extends AbstractASiCXAdESCounterSignatureTest {

	private ASiCWithXAdESService service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
		signingDate = new Date();
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		return signatureParameters;
	}

	@Override
	protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
		XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return signatureParameters;
	}
	
	@Override
	protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
		DSSDocument counterSigned = super.counterSign(signatureDocument, signatureId);
		return super.counterSign(counterSigned, signatureId);
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(3, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());
		
		AdvancedSignature advancedSignature = signatures.get(0);
		List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
		assertEquals(2, counterSignatures.size());
		
		assertNotEquals(counterSignatures.get(0).getId(), counterSignatures.get(1).getId());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// duplicated ids detected
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			if (signature.isCounterSignature()) {
				assertFalse(diagnosticData.isBLevelTechnicallyValid(signature.getId()));
			} else {
				assertTrue(diagnosticData.isBLevelTechnicallyValid(signature.getId()));
			}
		}
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isStructuralValidationValid());
		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getStructuralValidationMessages()));

		boolean duplicateIdErrorFound = false;
		for (String error : signatureWrapper.getStructuralValidationMessages()) {
			if (error.contains("There are multiple occurrences of ID value 'CS-")) {
				duplicateIdErrorFound = true;
			}
		}
		assertTrue(duplicateIdErrorFound);
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
