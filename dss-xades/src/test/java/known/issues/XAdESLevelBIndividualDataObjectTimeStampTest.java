package known.issues;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.xml.security.transforms.Transforms;
import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.TimestampService;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESLevelBIndividualDataObjectTimeStampTest extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters> {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_BASE64_DECODE);
		transforms.add(dssTransform);

		List<DSSReference> references = new ArrayList<DSSReference>();
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(documentToSign);
		dssReference.setId(documentToSign.getName());
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
		signatureParameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
		signatureParameters.setSignedPropertiesCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
		signatureParameters.setReferences(references);

		TimestampParameters contentTimestampParameters = new TimestampParameters();
		contentTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
		contentTimestampParameters.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
		signatureParameters.setContentTimestampParameters(contentTimestampParameters);

		try {
			TimestampService timestampService = new TimestampService(getGoodTsa(), new CertificatePool());
			TimestampToken timestampToken = timestampService.generateXAdESContentTimestampAsTimestampToken(documentToSign, signatureParameters,
					TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
			List<TimestampToken> contentTimestamps = new ArrayList<TimestampToken>();
			contentTimestamps.add(timestampToken);
			signatureParameters.setContentTimestamps(contentTimestamps);
		} catch (Exception e) {
			throw new DSSException("Error during MockTspSource", e);
		}

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected Reports getValidationReport(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(documentToSign);
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();
		return reports;
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
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
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
