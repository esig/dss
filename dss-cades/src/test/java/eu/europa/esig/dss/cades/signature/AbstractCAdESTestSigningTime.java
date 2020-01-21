package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;

public abstract class AbstractCAdESTestSigningTime extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private Date signingTime;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		
		signingTime = getSigningTime();
		signatureParameters.bLevel().setSigningDate(signingTime);

		service = new MockCAdESService(getCompleteCertificateVerifier());
	}
	
	protected abstract Date getSigningTime();
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		super.checkSigningDate(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signingTime.equals(signature.getClaimedSigningTime()));
	}

	@Override
	protected boolean isGenerateHtmlPdfReports() {
		return true;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	@SuppressWarnings("serial")
	protected class MockCAdESService extends CAdESService {

		public MockCAdESService(CertificateVerifier certificateVerifier) {
			super(certificateVerifier);
		}
		
		@Override
		protected void assertSigningDateInCertificateValidityRange(final CAdESSignatureParameters parameters) {
			// do nothing
		}
		
	}

}
