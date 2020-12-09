package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * The class is used to validate a {@code SignaturePolicy} and build a {@code XmlPolicy}
 *
 */
public class XmlPolicyBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XmlPolicyBuilder.class);

	/** The {@code SignaturePolicy} to incorporate into the DiagnosticData */
	private final SignaturePolicy signaturePolicy;

	/** Retrieves the signature policy document */
	private SignaturePolicyProvider signaturePolicyProvider;

	/** The found SignaturePolicyStore from a signature */
	private SignaturePolicyStore signaturePolicyStore;

	/** The DigestAlgorithm to use */
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/** The signature policy validator instance */
	private SignaturePolicyValidator validator;
	
	/**
	 * The default constructor
	 * 
	 * @param signaturePolicy {@link SignaturePolicy} to build {@code XmlPolicy} from
	 */
	public XmlPolicyBuilder(SignaturePolicy signaturePolicy) {
		Objects.requireNonNull(signaturePolicy, "SignaturePolicy cannot be null!");
		this.signaturePolicy = signaturePolicy;
	}
	
	/**
	 * Sets {@code SignaturePolicyProvider} to extract a SignaturePolicy by ID or URI
	 * 
	 * @param signaturePolicyProvider {@link SignaturePolicyProvider}
	 */
	public void setSignaturePolicyProvider(final SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
	}

	/**
	 * Sets {@code SignaturePolicyStore} extracted from a signature when applicable
	 * 
	 * @param signaturePolicyStore {@link SignaturePolicyStore}
	 */
	public void setSignaturePolicyStore(SignaturePolicyStore signaturePolicyStore) {
		this.signaturePolicyStore = signaturePolicyStore;
	}
	
	/**
	 * Sets a default {@code DigestAlgorithm} to compute a signature policy store digest,
	 * when SignaturePolicyIdentifier is not present
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.defaultDigestAlgorithm = digestAlgorithm;
	}
	
	/**
	 * Validates a {@code SignaturePolicy} and builds an {@code XmlPolicy}
	 * 
	 * @return {@link XmlPolicy}
	 */
	public XmlPolicy build() {
		DSSDocument policyContent = extractPolicyContent();
		signaturePolicy.setPolicyContent(policyContent);

		final XmlPolicy xmlPolicy = new XmlPolicy();

		xmlPolicy.setId(signaturePolicy.getIdentifier());
		xmlPolicy.setUrl(DSSUtils.removeControlCharacters(signaturePolicy.getUrl()));
		xmlPolicy.setDescription(signaturePolicy.getDescription());
		xmlPolicy.setDocumentationReferences(signaturePolicy.getDocumentationReferences());
		xmlPolicy.setNotice(signaturePolicy.getNotice());
		xmlPolicy.setZeroHash(signaturePolicy.isZeroHash());
		
		List<String> transformsDescription = signaturePolicy.getTransformsDescription();
		if (Utils.isCollectionNotEmpty(transformsDescription)) {
			xmlPolicy.setTransformations(transformsDescription);
		}

		final Digest digest = signaturePolicy.getDigest();
		if (digest != null) {
			xmlPolicy.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(digest.getAlgorithm(), digest.getValue()));
		}
		
		try {
			SignaturePolicyValidator validator = getValidator(signaturePolicy);
			validator.validate();
			
			xmlPolicy.setAsn1Processable(validator.isAsn1Processable());
			if (!signaturePolicy.isZeroHash()) {
				xmlPolicy.setDigestAlgorithmsEqual(validator.isDigestAlgorithmsEqual());
			}
			xmlPolicy.setIdentified(validator.isIdentified());
			xmlPolicy.setStatus(validator.isStatus());
			if (Utils.isStringNotBlank(validator.getProcessingErrors())) {
				xmlPolicy.setProcessingError(validator.getProcessingErrors());
			}
		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.getMessage());
			// Do nothing
			String errorMessage = "An error occurred during validation a signature policy with id '{}'. Reason : [{}]";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, signaturePolicy.getIdentifier(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, signaturePolicy.getIdentifier(), e.getMessage());
			}
		}
		
		return xmlPolicy;
	}
	
	/**
	 * Extracts {@code SignaturePolicy} content
	 * NOTE: the relevant {@code SignaturePolicyStore} or/and {@code SignaturePolicyProvider} shall be provided
	 * 
	 * @return {@link DSSDocument} representing a {@code SignaturePolicy} content, NULL if not available
	 */
	public DSSDocument extractPolicyContent() {
		if (signaturePolicyStore != null && signaturePolicyStore.getSignaturePolicyContent() != null) {
			return signaturePolicyStore.getSignaturePolicyContent();
		}
		
		if (signaturePolicyProvider != null) {
			return signaturePolicyProvider.getSignaturePolicy(signaturePolicy.getIdentifier(), signaturePolicy.getUrl());
		}
		
		throw new DSSException("Unable to extact a SignaturePolicy content. SignaturePolicyStore or SignaturePolicyProvider shall be provided.");
	}
	
	/**
	 * Builds an {@code XmlSignaturePolicyStore}
	 * 
	 * @return {@link XmlSignaturePolicyStore}
	 */
	public XmlSignaturePolicyStore buildSignaturePolicyStore() {
		if (signaturePolicyStore == null) {
			return null;
		}
		XmlSignaturePolicyStore xmlSignaturePolicyStore = new XmlSignaturePolicyStore();
		SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
		if (spDocSpecification != null) {
			xmlSignaturePolicyStore.setId(spDocSpecification.getId());
			xmlSignaturePolicyStore.setDescription(spDocSpecification.getDescription());
			String[] documentationReferences = spDocSpecification.getDocumentationReferences();
			if (Utils.isArrayNotEmpty(documentationReferences)) {
				xmlSignaturePolicyStore.setDocumentationReferences(Arrays.asList(documentationReferences));
			}
		}
		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent != null) {
			DigestAlgorithm digestAlgorithm = defaultDigestAlgorithm;
			if (signaturePolicy != null && signaturePolicy.getDigest() != null) {
				digestAlgorithm = signaturePolicy.getDigest().getAlgorithm();
			}
			SignaturePolicyValidator validator = getValidator(signaturePolicy);
			Digest recalculatedDigest = validator.getComputedDigest(digestAlgorithm);
			xmlSignaturePolicyStore.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(recalculatedDigest.getAlgorithm(), recalculatedDigest.getValue()));
		}
		return xmlSignaturePolicyStore;
	}
	
	private SignaturePolicyValidator getValidator(SignaturePolicy signaturePolicy) {
		if (validator == null) {
			validator = new SignaturePolicyValidatorLoader(signaturePolicy).loadValidator();
		}
		return validator;
	}

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(DigestAlgorithm digestAlgo, byte[] digestValue) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo);
		xmlDigestAlgAndValue.setDigestValue(digestValue == null ? DSSUtils.EMPTY_BYTE_ARRAY : digestValue);
		return xmlDigestAlgAndValue;
	}

}
