package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;

public class XAdESLevelBEnvelopedWithReferenceByIdNoTransformTest extends AbstractXAdESTestSignature {

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
		
		DSSReference dssReferenceWholeDocument = new DSSReference();
		dssReferenceWholeDocument.setId("r-wholeDocument");
		dssReferenceWholeDocument.setUri("");
		dssReferenceWholeDocument.setContents(documentToSign);
		dssReferenceWholeDocument.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		dssReferenceWholeDocument.setTransforms(Arrays.asList(new XPath2FilterEnvelopedSignatureTransform()));
		references.add(dssReferenceWholeDocument);
		
		DSSReference dssReferenceById = new DSSReference();
		dssReferenceById.setId("r-byId");
		dssReferenceById.setUri("#hello");
		dssReferenceById.setContents(documentToSign);
		dssReferenceById.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		references.add(dssReferenceById);

		signatureParameters.setReferences(references);

		service = new XAdESService(getCompleteCertificateVerifier());
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
