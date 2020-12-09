package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Signature parameters for a Trusted List creation
 * 
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 */
public class TrustedListSignatureParametersBuilder extends AbstractSignatureParametersBuilder<XAdESSignatureParameters> {
	
	/**
	 * The EXCLUSIVE canonicalization shall be used
	 * See TS 119 612 "B.1 The Signature element"
	 */
	private final static String DEFAULT_CANONICALIZATION = CanonicalizationMethod.EXCLUSIVE;

	/** The default prefix for an enveloped signature reference id */
	private final static String DEFAULT_REFERENCE_PREFIX = "enveloped-signature-";
	
	/**
	 * The XML Trusted List document
	 */
	private final DSSDocument tlXmlDocument;
	
	/**
	 * The Enveloped reference Id to use
	 */
	private String referenceId;
	
	/**
	 * The DigestAlgorithm to be used for an Enveloped reference
	 */
	private DigestAlgorithm referenceDigestAlgorithm = DigestAlgorithm.SHA256;
	
	/**
	 * The constructor to build Signature Parameters for a Trusted List signing with respect to ETSI TS 119 612
	 * 
	 * @param signingCertificate {@link CertificateToken} to be used for a signature creation
	 * @param tlXmlDocument {@link DSSDocument} Trusted List XML document to be signed
	 */
	public TrustedListSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
		this(signingCertificate, new LinkedList<>(), tlXmlDocument);
	}
	/**
	 * The default constructor to build Signature Parameters for a Trusted List signing with respect to ETSI TS 119 612
	 * 
	 * @param signingCertificate {@link CertificateToken} to be used for a signature creation
	 * @param certificateChain a list of {@link CertificateToken}s representing a certificate chain
	 * @param tlXmlDocument {@link DSSDocument} Trusted List XML document to be signed
	 */
	public TrustedListSignatureParametersBuilder(CertificateToken signingCertificate, List<CertificateToken> certificateChain, DSSDocument tlXmlDocument) {
		super(signingCertificate, certificateChain);
		this.tlXmlDocument = tlXmlDocument;
	}

	/**
	 * Sets an Enveloped Reference Id to use
	 * 
	 * @param referenceId {@link String} reference Id
	 * @return this builder
	 */
	public TrustedListSignatureParametersBuilder setReferenceId(String referenceId) {
		this.referenceId = referenceId;
		return this;
	}

	/**
	 * Sets an Enveloped Reference {@code DigestAlgorithm} to use
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used
	 * @return this builder
	 */
	public TrustedListSignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.referenceDigestAlgorithm = digestAlgorithm;
		return this;
	}

	@Override
	protected XAdESSignatureParameters initParameters() {
		return new XAdESSignatureParameters();
	}
	
	@Override
	public XAdESSignatureParameters build() {
		XAdESSignatureParameters signatureParameters = super.build();
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEn319132(false);
		
		final List<DSSReference> references = new ArrayList<>();

		DSSReference dssReference = new DSSReference();
		if (referenceId != null) {
			dssReference.setId(referenceId);
		} else {
			dssReference.setId(DEFAULT_REFERENCE_PREFIX + signatureParameters.getDeterministicId());
		}
		dssReference.setUri("");
		dssReference.setContents(tlXmlDocument);
		dssReference.setDigestMethodAlgorithm(referenceDigestAlgorithm);

		final List<DSSTransform> transforms = new ArrayList<>();

		EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
		transforms.add(signatureTransform);

		CanonicalizationTransform dssTransform = new CanonicalizationTransform(DEFAULT_CANONICALIZATION);
		transforms.add(dssTransform);

		dssReference.setTransforms(transforms);
		references.add(dssReference);

		signatureParameters.setReferences(references);
		
		return signatureParameters;
	}

}
