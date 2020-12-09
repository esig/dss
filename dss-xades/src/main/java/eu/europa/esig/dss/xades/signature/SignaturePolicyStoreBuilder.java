package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Paths;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Paths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Attribute;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Arrays;
import java.util.Objects;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * Builds a XAdES SignaturePolicyStore
 */
public class SignaturePolicyStoreBuilder extends ExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyStoreBuilder.class);

	/**
	 * Default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	protected SignaturePolicyStoreBuilder(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds a signaturePolicyStore to all signatures inside the document
	 *
	 * @param document {@link DSSDocument} containing signatures to add signature policy store into
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} with signaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSignaturePolicyContent(), "Signature policy content must be provided");

		params = new XAdESSignatureParameters();

		documentDom = DomUtils.buildDOM(document);

		final NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, XMLDSigElement.SIGNATURE.getTagName());
		if (signatureNodeList.getLength() == 0) {
			throw new DSSException("No signature to extend!");
		}

		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {
			currentSignatureDom = (Element) signatureNodeList.item(ii);

			xadesSignature = new XAdESSignature(currentSignatureDom, Arrays.asList(new XAdES111Paths(), new XAdES122Paths(), new XAdES132Paths()));

			xadesPaths = xadesSignature.getXAdESPaths();
			
			final String currentSignatureId = xadesSignature.getDAIdentifier();

			ensureUnsignedProperties();
			ensureUnsignedSignatureProperties();

			SignaturePolicy signaturePolicy = xadesSignature.getSignaturePolicy();
			if (signaturePolicy != null) {
				final Digest digest = signaturePolicy.getDigest();
				if (digest != null) {
					signaturePolicy.setPolicyContent(signaturePolicyStore.getSignaturePolicyContent());
					
					SignaturePolicyValidator validator = new SignaturePolicyValidatorLoader(signaturePolicy).loadValidator();
					Digest computedDigest = validator.getComputedDigest(digest.getAlgorithm());
					if (digest.equals(computedDigest)) {

						Element signaturePolicyStoreElement = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, getXades141Namespace(),
								XAdES141Element.SIGNATURE_POLICY_STORE);
						
						if (signaturePolicyStore.getId() != null) {
							signaturePolicyStoreElement.setAttribute(XAdES141Attribute.ID.getAttributeName(), signaturePolicyStore.getId());
						}

						SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();

						Element spDocSpecElement = DomUtils.addElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
								XAdES141Element.SP_DOC_SPECIFICATION);

						Element identifierElement = DomUtils.addElement(documentDom, spDocSpecElement,
								getXadesNamespace(), getCurrentXAdESElements().getElementIdentifier());
						if (spDocSpecification.getQualifier() != null) {
							identifierElement.setAttribute(XAdES132Attribute.QUALIFIER.getAttributeName(), spDocSpecification.getQualifier().getValue());
						}
						DomUtils.setTextNode(documentDom, identifierElement, spDocSpecification.getId());

						if (Utils.isStringNotEmpty(spDocSpecification.getDescription())) {
							Element descriptionElement = DomUtils.addElement(documentDom, spDocSpecElement, getXadesNamespace(),
									getCurrentXAdESElements().getElementDescription());
							DomUtils.setTextNode(documentDom, descriptionElement, spDocSpecification.getDescription());
						}

						if (Utils.isArrayNotEmpty(spDocSpecification.getDocumentationReferences())) {
							Element documentReferencesElement = DomUtils.addElement(documentDom, spDocSpecElement, getXadesNamespace(),
									getCurrentXAdESElements().getElementDocumentationReferences());

							for (String docRef : spDocSpecification.getDocumentationReferences()) {
								Element documentReferenceElement = DomUtils.addElement(documentDom, documentReferencesElement, getXadesNamespace(),
										getCurrentXAdESElements().getElementDocumentationReference());
								DomUtils.setTextNode(documentDom, documentReferenceElement, docRef);
							}
						}

						Element policyDocElement = DomUtils.addElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
								XAdES141Element.SIGNATURE_POLICY_DOCUMENT);

						DomUtils.setTextNode(documentDom, policyDocElement,
								Utils.toBase64(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));

					} else {
						LOG.warn("Signature policy's digest doesn't match the document {} for signature {}", digest, currentSignatureId);
					}
				} else {
					LOG.warn("No defined digest for signature {}", currentSignatureId);
				}
			} else {
				LOG.warn("No defined SignaturePolicyIdentifier for signature {}", currentSignatureId);
			}
		}

		return createXmlDocument();
	}

}
