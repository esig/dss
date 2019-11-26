package eu.europa.esig.dss.ws.timestamp.remote;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class RemoteTimestampServiceTest extends PKIFactoryAccess {
	
	private RemoteTimestampService timestampService;
	
	@BeforeEach
	public void init() {
		timestampService = new RemoteTimestampService();
		timestampService.setTSPSource(getGoodTsa());
	}
	
	@Test
	public void simpleTest() {
		byte[] contentToBeTimestamped = "Hello World!".getBytes();
		byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA1, contentToBeTimestamped);
		TimestampResponseDTO timestampResponse = timestampService.getTimestampResponse(DigestAlgorithm.SHA1, digestValue);
		assertNotNull(timestampResponse);
		assertTrue(Utils.isArrayNotEmpty(timestampResponse.getBinaries()));
	}
	
	@Test
	public void signatureWithContentTimestamp() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		
		String canonicalizationAlgo = CanonicalizationMethod.EXCLUSIVE;
		DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(digestAlgorithm);
		
		byte[] digest = DSSUtils.digest(digestAlgorithm, DSSXMLUtils.canonicalize(canonicalizationAlgo, DSSUtils.toByteArray(documentToSign)));
		TimestampResponseDTO timeStampResponse = timestampService.getTimestampResponse(digestAlgorithm, digest);
		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBinaries(), TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		timestampToken.setCanonicalizationMethod(canonicalizationAlgo);
		signatureParameters.setContentTimestamps(Arrays.asList(timestampToken));
		
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setIncludeTimestampTokenValues(true);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertNotNull(timestampList);
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestamp = timestampList.get(0);
		assertTrue(timestamp.getType().isContentTimestamp());
		assertEquals(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, timestamp.getType());
		assertTrue(Arrays.equals(timeStampResponse.getBinaries(), timestamp.getBinaries()));
	}
	
	@Test
	public void noTSPSourceDefinedTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> {
			RemoteTimestampService remoteTimestampService = new RemoteTimestampService();
			byte[] contentToBeTimestamped = "Hello World!".getBytes();
			byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA1, contentToBeTimestamped);
			remoteTimestampService.getTimestampResponse(DigestAlgorithm.SHA1, digestValue);
		});
		assertEquals("TSPSource must be not null!", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
