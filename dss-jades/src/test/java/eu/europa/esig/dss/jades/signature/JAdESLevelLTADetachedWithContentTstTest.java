package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESLevelLTADetachedWithContentTstTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private JAdESService service;
	private List<DSSDocument> documentsToSign;
	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentsToSign = new ArrayList<>();
		documentsToSign.add(new FileDocument(new File("src/test/resources/sample.json")));
		documentsToSign.add(new InMemoryDocument("Hello World!".getBytes(), "HelloWorld"));
		signingDate = new Date();
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

		TimestampToken contentTimestamp = service.getContentTimestamp(documentsToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
		
		return signatureParameters;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		assertEquals(3, diagnosticData.getTimestampList().size());
		
		boolean contentTstFound = false;
		boolean archiveTstFound = false;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (timestampWrapper.getType().isContentTimestamp()) {
				assertEquals(2, timestampWrapper.getTimestampedSignedData().size());
				contentTstFound = true;
			}
			if (timestampWrapper.getType().isArchivalTimestamp()) {
				assertEquals(2, timestampWrapper.getTimestampedSignedData().size());
				archiveTstFound = true;
			}
		}
		assertTrue(contentTstFound);
		assertTrue(archiveTstFound);
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		assertEquals(2, diagnosticData.getOriginalSignerDocuments().size());
	}

	@Override
	protected List<DSSDocument> getDetachedContents() {
		return documentsToSign;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	@Override
	protected MimeType getExpectedMime() {
		return MimeType.JOSE_JSON;
	}

}
