package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class XAdESLevelTCounterSignatureTest extends AbstractXAdESCounterSignatureTest {

	private XAdESService service;
	private DSSDocument signedDocument;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		signedDocument = new FileDocument(new File("src/test/resources/sample-counter-signed.xml"));
		signingDate = new Date();
	}
	
	@Override
	protected DSSDocument sign() {
		return signedDocument;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return getCounterSignatureParameters();
	}

	@Override
	protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
		XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		return signatureParameters;
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		
		AdvancedSignature signature = signatures.iterator().next();
		assertEquals(2, signature.getCounterSignatures().size());
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(3, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// do nothing
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return signedDocument;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
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
