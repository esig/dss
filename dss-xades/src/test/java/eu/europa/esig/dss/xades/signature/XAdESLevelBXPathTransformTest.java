package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;

public class XAdESLevelBXPathTransformTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample-with-different-id.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		List<DSSReference> references = new ArrayList<DSSReference>();
		
		DSSReference dssReference = new DSSReference();
		dssReference.setId("DSS-REF-1");
		dssReference.setUri("");
		dssReference.setContents(documentToSign);
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		DSSTransform xPathTransform = new XPathTransform("ancestor-or-self::*[@Id='hello']");
		dssReference.setTransforms(Arrays.asList(xPathTransform));
		references.add(dssReference);

		signatureParameters.setReferences(references);

		service = new XAdESService(getCompleteCertificateVerifier());
	}
	
	protected void getOriginalDocument(DSSDocument signedDocument, DiagnosticData diagnosticData) throws IOException {
		// the reference output does not equal to the original file content
		// do nothing
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
