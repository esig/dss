package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class XAdESLevelBEnvelopingCounterSignatureTest extends AbstractXAdESCounterSignatureTest {

	private XAdESService service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		signingDate = new Date();
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return signatureParameters;
	}

	@Override
	protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
		XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setLocality("Kehlen");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfCreation));
		return signatureParameters;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		boolean counterSignatureFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				counterSignatureFound = true;
				
				boolean counterSignatureDMFound = false;
				boolean signedPropertiesDMFound = false;
				assertEquals(2, signatureWrapper.getDigestMatchers().size());
				for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
					if (DigestMatcherType.COUNTER_SIGNATURE.equals(digestMatcher.getType())) {
						counterSignatureDMFound = true;
					} else if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
						signedPropertiesDMFound = true;
					}
				}
				assertTrue(counterSignatureDMFound);
				assertTrue(signedPropertiesDMFound);
			}
		}
		assertTrue(counterSignatureFound);
	}
	
	@Override
	protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
		super.checkCommitmentTypeIndications(diagnosticData);
		
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<XmlCommitmentTypeIndication> commitmentTypeIndications = signature.getCommitmentTypeIndications();
			if (signature.isCounterSignature()) {
				assertEquals(1, commitmentTypeIndications.size());
				XmlCommitmentTypeIndication commitmentTypeIndication = commitmentTypeIndications.get(0);
				assertEquals(CommitmentTypeEnum.ProofOfCreation.getUri(), commitmentTypeIndication.getIdentifier());
				assertEquals(CommitmentTypeEnum.ProofOfCreation.getDescription(), commitmentTypeIndication.getDescription());
				assertEquals(CommitmentTypeEnum.ProofOfCreation.getDocumentationReferences().length, 
						commitmentTypeIndication.getDocumentationReferences().size());
			} else {
				assertEquals(0, commitmentTypeIndications.size());
			}
		}
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
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
