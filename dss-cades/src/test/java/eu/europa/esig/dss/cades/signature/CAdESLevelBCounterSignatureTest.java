package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class CAdESLevelBCounterSignatureTest extends AbstractCAdESCounterSignatureTest {

	private CAdESService service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new InMemoryDocument("Hello World".getBytes());
		signingDate = new Date();
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		return signatureParameters;
	}

	@Override
	protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
		CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setLocality("Kehlen");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfCreation));
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		boolean counterSignatureFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
				assertEquals(1, signatureScopes.size());
				
				XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
				assertEquals(SignatureScopeType.COUNTER_SIGNATURE, xmlSignatureScope.getScope());
				assertEquals(signatureWrapper.getParent().getId(), xmlSignatureScope.getName());
				
				counterSignatureFound = true;
			}
		}
		assertTrue(counterSignatureFound);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
