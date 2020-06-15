package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class DSS1334SignatureTest extends AbstractXAdESTestSignature {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = ORIGINAL_FILE;
		documentToSign.setName(null);

		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
	}

	@Test
	public void extendValidFile() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");

		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setDetachedContents(Arrays.<DSSDocument>asList(ORIGINAL_FILE));
		
		DSSDocument extendedDocument = service.extendDocument(doc, parameters);
		assertNotNull(extendedDocument);
	}

	@Test
	public void extendInvalidFile() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");

		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setDetachedContents(Arrays.<DSSDocument>asList(ORIGINAL_FILE));
		Exception exception = assertThrows(DSSException.class, () -> service.extendDocument(doc, parameters));
		assertEquals("Cryptographic signature verification has failed / Certificate #1: Signature verification failed", exception.getMessage());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.<DSSDocument>asList(ORIGINAL_FILE);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
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

}
