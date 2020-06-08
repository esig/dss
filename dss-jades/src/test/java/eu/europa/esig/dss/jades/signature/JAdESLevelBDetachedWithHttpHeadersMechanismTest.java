package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.jades.HTTPHeaderDocument;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;

public class JAdESLevelBDetachedWithHttpHeadersMechanismTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private List<DSSDocument> documentsToSign;
	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		JAdESService jadesService = new JAdESService(getCompleteCertificateVerifier());
		jadesService.setTspSource(getGoodTsa());
		service = jadesService;
		
		signingDate = new Date();
		
		documentsToSign = new ArrayList<>();
		documentsToSign.add(new HTTPHeaderDocument("content-type", "application/json"));
		documentsToSign.add(new HTTPHeaderDocument("x-example", "HTTP Headers Example"));
		documentsToSign.add(new HTTPHeaderDocument("x-example", "Duplicated Header"));
		
		DSSDocument messageBodyDocument = new FileDocument("src/test/resources/sample.json");
		String digest = messageBodyDocument.getDigest(DigestAlgorithm.SHA1);
		documentsToSign.add(new HTTPHeaderDocument("Digest", "SHA="+digest));
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		signatureParameters.setSigDMechanism(SigDMechanism.HTTP_HEADERS);
		return signatureParameters;
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		// change order
		List<DSSDocument> detachedContents = new ArrayList<>();

		detachedContents.add(new HTTPHeaderDocument("x-example", "HTTP Headers Example"));
		DSSDocument messageBodyDocument = new FileDocument("src/test/resources/sample.json");
		String digest = messageBodyDocument.getDigest(DigestAlgorithm.SHA1);
		detachedContents.add(new HTTPHeaderDocument("Digest", "SHA="+digest));
		detachedContents.add(new HTTPHeaderDocument("content-type", "application/json"));
		detachedContents.add(new HTTPHeaderDocument("x-example", "Duplicated Header"));
		
		return detachedContents;
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals("HttpHeaders payload", xmlSignatureScope.getName());
		assertEquals("Payload value digest", xmlSignatureScope.getDescription());
		assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		assertNotNull(xmlSignatureScope.getSignerData());
		assertTrue(Utils.isCollectionEmpty(xmlSignatureScope.getTransformations()));
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
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

}
