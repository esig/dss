package eu.europa.esig.dss.jades.signature.counter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.counter.CounterSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class JAdESLevelBCounterSignatureTest extends AbstractJAdESCounterSignatureTest {

	private JAdESService service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signingDate = new Date();
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
		return signatureParameters;
	}

	@Override
	protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
		JAdESCounterSignatureParameters signatureParameters = new JAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setLocality("Kehlen");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfCreation));
		return signatureParameters;
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(new InMemoryDocument(byteArray));
		assertTrue(jwsJsonSerializationParser.isSupported());
		
		JWSJsonSerializationObject jsonSerializationObject = jwsJsonSerializationParser.parse();
		List<JWS> jwsSignatures = jsonSerializationObject.getSignatures();
		assertEquals(1, jwsSignatures.size());
		
		JWS jws = jwsSignatures.iterator().next();
		List<Object> etsiU = JAdESUtils.getEtsiU(jws);
		assertEquals(1, etsiU.size());
		
		Map<?, ?> item = (Map<?, ?>) etsiU.iterator().next();
		assertEquals(1, item.size());
		
		String cSig = (String) item.get(JAdESHeaderParameterNames.C_SIG);
		assertNotNull(cSig);
		
		JWSCompactSerializationParser compactSerializationParser = new JWSCompactSerializationParser(new InMemoryDocument(cSig.getBytes()));
		assertTrue(compactSerializationParser.isSupported());
		
		JWS counterJWS = compactSerializationParser.parse();
		assertNotNull(counterJWS);
		assertNotNull(counterJWS.getEncodedHeader());
		assertNotNull(counterJWS.getSignatureValue());
		assertTrue(Utils.isArrayEmpty(counterJWS.getUnverifiedPayloadBytes()));
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
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

		JAdESSignature jadesSignature = (JAdESSignature) advancedSignatures.get(0);
		JWS jws = jadesSignature.getJws();
		
		JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();
		jwsJsonSerializationObject.getSignatures().add(jws);
		jwsJsonSerializationObject.setJWSSerializationType(getSignatureParameters().getJwsSerializationType());
		
		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(
				jwsJsonSerializationObject, getSignatureParameters().getJwsSerializationType());
		
		DSSDocument signatureDocument = new InMemoryDocument(generator.generate());

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			XmlDigestAlgoAndValue dtbsr = signature.getDataToBeSignedRepresentation();
			
			ToBeSigned dataToSign;
			if (signature.isCounterSignature()) {
				dataToSign = service.getDataToBeCounterSigned(signatureDocument, getCounterSignatureParameters());
			} else {
				dataToSign = service.getDataToSign(documentToSign, getSignatureParameters());
			}
			assertArrayEquals(DSSUtils.digest(dtbsr.getDigestMethod(), dataToSign.getBytes()), dtbsr.getDigestValue());
		}
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
