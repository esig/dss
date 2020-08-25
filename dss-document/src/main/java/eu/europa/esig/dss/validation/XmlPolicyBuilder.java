package eu.europa.esig.dss.validation;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.BasicASNSignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;

/**
 * The class is used to validate a {@code SignaturePolicy} and build a {@code XmlPolicy}
 *
 */
public class XmlPolicyBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XmlPolicyBuilder.class);
	
	private final SignaturePolicy signaturePolicy;
	
	private SignaturePolicyProvider signaturePolicyProvider;
	private SignaturePolicyStore signaturePolicyStore;
	
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
	
	private SignaturePolicyValidator getValidator(SignaturePolicy signaturePolicy) {
		SignaturePolicyValidator validator = null;
		ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
		Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

		if (validatorOptions.hasNext()) {
			for (SignaturePolicyValidator signaturePolicyValidator : loader) {
				signaturePolicyValidator.setSignaturePolicy(signaturePolicy);
				if (signaturePolicyValidator.canValidate()) {
					validator = signaturePolicyValidator;
					break;
				}
			}
		}

		if (validator == null) {
			// if not empty and no other implementation is found for ASN1 signature policies
			validator = new BasicASNSignaturePolicyValidator();
			validator.setSignaturePolicy(signaturePolicy);
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
