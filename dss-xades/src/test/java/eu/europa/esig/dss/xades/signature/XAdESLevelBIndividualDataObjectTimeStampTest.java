package eu.europa.esig.dss.xades.signature;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Transform;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampInclude;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBIndividualDataObjectTimeStampTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		String referenceId = "TOTO";

		// Canonicalization is optional
		String canonicalizationAlgo = CanonicalizationMethod.EXCLUSIVE;

		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transform.BASE64);
		transforms.add(dssTransform);

		List<DSSReference> references = new ArrayList<DSSReference>();
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(documentToSign);
		dssReference.setId(referenceId);
		dssReference.setUri("#" + documentToSign.getName());
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA1);
		dssReference.setTransforms(transforms);
		dssReference.setType("text/xml");
		references.add(dssReference);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(references);

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, DSSXMLUtils.canonicalize(canonicalizationAlgo, DSSUtils.toByteArray(documentToSign)));
		TimeStampToken timeStampResponse = getAlternateGoodTsa().getTimeStampResponse(DigestAlgorithm.SHA1, digest);
		TimestampToken timestampToken = new TimestampToken(timeStampResponse, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		timestampToken.setTimestampIncludes(Arrays.asList(new TimestampInclude(referenceId, true)));
		timestampToken.setCanonicalizationMethod(canonicalizationAlgo);
		signatureParameters.setContentTimestamps(Arrays.asList(timestampToken));

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(documentToSign);
		validator.setDetachedContents(detachedContents);
		return validator;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
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
