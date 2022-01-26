/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SignatureBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.ReferenceBuilder;
import eu.europa.esig.dss.xades.reference.ReferenceProcessor;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * This class implements all the necessary mechanisms to build each form of the XML signature.
 *
 */
public abstract class XAdESSignatureBuilder extends XAdESBuilder implements SignatureBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureBuilder.class);

	/**
	 * Indicates if the signature was already built. (Two steps building)
	 */
	protected boolean built = false;

	/**
	 * This is the reference to the original document to sign
	 */
	protected DSSDocument document;

	/** The canonicalication method used for KeyInfo signing */
	protected String keyInfoCanonicalizationMethod;

	/** The canonicalication method used for SignedInfo signing */
	protected String signedInfoCanonicalizationMethod;

	/** The canonicalication method used for SignedProperties signing */
	protected String signedPropertiesCanonicalizationMethod;

	/** The deterministic Id used for elements creation */
	protected final String deterministicId;

	/** This variable represents the current DOM signature object. */
	protected Element signatureDom;

	/** Cached KeyInfo element */
	protected Element keyInfoDom;
	/** Cached SignedInfo element */
	protected Element signedInfoDom;
	/** Cached SignatureValue element */
	protected Element signatureValueDom;
	/** Cached QualifyingProperties element */
	protected Element qualifyingPropertiesDom;
	/** Cached SignedProperties element */
	protected Element signedPropertiesDom;
	/** Cached SignedSignatureProperties element */
	protected Element signedSignaturePropertiesDom;
	/** Cached SignedDataObjectProperties element */
	protected Element signedDataObjectPropertiesDom;
	/** Cached UnsignedSignatureProperties element */
	protected Element unsignedSignaturePropertiesDom;

	/** Id-suffix for KeyInfo element */
	protected static final String KEYINFO_SUFFIX = "keyInfo-";
	/** Id-suffix for Timestamp element */
	protected static final String TIMESTAMP_SUFFIX = "TS-";
	/** Id-suffix for SignatureValue element */
	protected static final String VALUE_SUFFIX = "value-";
	/** Id-suffix for Signature element */
	protected static final String XADES_SUFFIX = "xades-";

	/**
	 * Creates the signature according to the packaging
	 *
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 *            the certificate verifier with its OCSPSource,...
	 * @return the signature builder linked to the packaging
	 */
	public static XAdESSignatureBuilder getSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document,
			final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(params.getSignaturePackaging(), "Cannot create a SignatureBuilder. SignaturePackaging is not defined!");
		
		switch (params.getSignaturePackaging()) {
			case ENVELOPED:
				return new EnvelopedSignatureBuilder(params, document, certificateVerifier);
			case ENVELOPING:
				return new EnvelopingSignatureBuilder(params, document, certificateVerifier);
			case DETACHED:
				return new DetachedSignatureBuilder(params, document, certificateVerifier);
			case INTERNALLY_DETACHED:
				return new InternallyDetachedSignatureBuilder(params, document, certificateVerifier);
			default:
				throw new DSSException("Unsupported packaging " + params.getSignaturePackaging());
		}
	}

	/**
	 * The default constructor for SignatureBuilder.
	 *
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 *            the certificate verifier with its OCSPSource,...
	 */
	protected XAdESSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document, final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		
		this.params = params;
		this.document = document;
		this.deterministicId = params.getDeterministicId();
		
		setCanonicalizationMethods(params);
	}
	
	private void setCanonicalizationMethods(final XAdESSignatureParameters params) {
		this.keyInfoCanonicalizationMethod = params.getKeyInfoCanonicalizationMethod();
		this.signedInfoCanonicalizationMethod = params.getSignedInfoCanonicalizationMethod();
		this.signedPropertiesCanonicalizationMethod = params.getSignedPropertiesCanonicalizationMethod();
	}

	/**
	 * This is the main method which is called to build the XML signature
	 *
	 * @return A byte array is returned with XML that represents the canonicalized SignedInfo segment of signature.
	 *         This data are used to define the SignatureValue element.
	 * @throws DSSException
	 *             if an error occurred
	 */
	public byte[] build() throws DSSException {

		assertSignaturePossible();

		ensureConfigurationValidity();
		
		xadesPaths = getCurrentXAdESPaths();

		documentDom = buildRootDocumentDom();

		incorporateFiles();

		incorporateSignatureDom();

		incorporateSignedInfo();

		incorporateSignatureValue();

		incorporateKeyInfo();

		incorporateObjects();

		/**
		 * We create <ds:Reference> segment only now, because we need first to define the SignedProperties segment to
		 * calculate the digest of references.
		 */
		if (Utils.isArrayEmpty(params.getSignedData())) {
			incorporateReferences();
			incorporateReferenceSignedProperties();
			incorporateReferenceKeyInfo();
		}

		// Preparation of SignedInfo
		byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, getNodeToCanonicalize(signedInfoDom));
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignedInfo         --> {}", new String(canonicalizedSignedInfo));
			final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedSignedInfo);
			LOG.trace("Canonicalized SignedInfo SHA256  --> {}", Utils.toBase64(digest));
		}
		built = true;
		return canonicalizedSignedInfo;
	}
	
	private void assertSignaturePossible() {
		if (DomUtils.isDOM(document)) {
			Document dom = DomUtils.buildDOM(document);
			final NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(dom);
			if (signatureNodeList != null && signatureNodeList.getLength() > 0) {
				for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {
					final Node signatureNode = signatureNodeList.item(ii);
					assertDoesNotContainEnvelopedTransform(signatureNode);
				}
			}
		}
	}

	private void assertDoesNotContainEnvelopedTransform(final Node signatureNode) {
		NodeList referenceNodeList = DSSXMLUtils.getReferenceNodeList(signatureNode);
		if (referenceNodeList != null && referenceNodeList.getLength() > 0) {
			for (int ii = 0; ii < referenceNodeList.getLength(); ii++) {
				final Node referenceNode = referenceNodeList.item(ii);
				NodeList transformList = DomUtils.getNodeList(referenceNode, XMLDSigPaths.TRANSFORMS_TRANSFORM_PATH);
				if (transformList != null && transformList.getLength() > 0) {
					for (int jj = 0; jj < transformList.getLength(); jj++) {
						final Element transformElement = (Element) transformList.item(jj);
						String transformAlgorithm = transformElement
								.getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
						if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(transformAlgorithm)) {
							throw new IllegalInputException(String.format(
									"The parallel signature is not possible! The provided file contains a signature with an '%s' transform.",
									Transforms.TRANSFORM_ENVELOPED_SIGNATURE));
						}
					}
				}
			}
		}
	}

	private void ensureConfigurationValidity() {
		checkSignaturePackagingValidity();

		ReferenceBuilder referenceBuilder = initReferenceBuilder();
		final List<DSSReference> references = params.getReferences();
		if (Utils.isCollectionEmpty(references)) {
			final List<DSSReference> defaultReferences = referenceBuilder.build();
			// The SignatureParameters object is updated with the default references
			// in order to ensure validity on next steps
			params.setReferences(defaultReferences);
		} else {
			referenceBuilder.checkReferencesValidity();
		}
	}

	private ReferenceBuilder initReferenceBuilder() {
		List<DSSDocument> detachedContent = Utils.isCollectionNotEmpty(params.getDetachedContents()) ?
				params.getDetachedContents() : Arrays.asList(document);
		return new ReferenceBuilder(detachedContent, params);
	}
	
	private void checkSignaturePackagingValidity() {
		if (!SignaturePackaging.ENVELOPING.equals(params.getSignaturePackaging())) {
			if (params.isManifestSignature()) {
				throw new IllegalArgumentException(String.format("The signature packaging %s is not compatible with manifestSignature(true) configuration!",
						params.getSignaturePackaging()));
			}
			if (params.isEmbedXML()) {
				throw new IllegalArgumentException(String.format("The signature packaging %s is not compatible with embedXML(true) configuration!",
						params.getSignaturePackaging()));
			}
		}
	}

	/**
	 * This method is used to incorporate the provided documents within the final file
	 */
	protected void incorporateFiles() {
		// not implemented by default
	}

	/**
	 * Builds an empty {@code Document}
	 *
	 * @return {@link Document}
	 */
	protected Document buildRootDocumentDom() {
		return DomUtils.buildDOM();
	}

	/**
	 * This method creates a new instance of Signature element.
	 */
	public void incorporateSignatureDom() {
		signatureDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.SIGNATURE);
		DomUtils.addNamespaceAttribute(signatureDom, getXmldsigNamespace());
		signatureDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), deterministicId);

		final Node parentNodeOfSignature = getParentNodeOfSignature();
		incorporateSignatureDom(parentNodeOfSignature);
	}

	/**
	 * Returns a parent node of the signature
	 *
	 * @return {@link Node}
	 */
	protected Node getParentNodeOfSignature() {
		return documentDom;
	}

	/**
	 * Incorporates the signature element to the parent node
	 *
	 * @param parentNodeOfSignature {@link Node} the parent node
	 */
	protected void incorporateSignatureDom(Node parentNodeOfSignature) {
		parentNodeOfSignature.appendChild(signatureDom);
	}

	/**
	 * This method incorporates the SignedInfo tag
	 *
	 * <pre>
	 *  {@code
	 *   	<ds:SignedInfo>
	 * 			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 *   		<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
	 *   		...
	 *   	</ds:SignedInfo>
	 *  }
	 * </pre>
	 */
	public void incorporateSignedInfo() {
		if (Utils.isArrayNotEmpty(params.getSignedData())) {
			LOG.debug("Using explicit SignedInfo from parameter");
			signedInfoDom = DomUtils.buildDOM(params.getSignedData()).getDocumentElement();
			signedInfoDom = (Element) documentDom.importNode(signedInfoDom, true);
			signatureDom.appendChild(signedInfoDom);
			return;
		}

		signedInfoDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.SIGNED_INFO);
		signatureDom.appendChild(signedInfoDom);
		incorporateCanonicalizationMethod(signedInfoDom, signedInfoCanonicalizationMethod);

		final Element signatureMethod = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.SIGNATURE_METHOD);
		signedInfoDom.appendChild(signatureMethod);		
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		final MaskGenerationFunction mgf = params.getMaskGenerationFunction();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, mgf);
		final String signatureAlgorithmXMLId = signatureAlgorithm.getUri();
		if (Utils.isStringBlank(signatureAlgorithmXMLId)) {
			throw new UnsupportedOperationException("Unsupported signature algorithm " + signatureAlgorithm);
		}
		signatureMethod.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), signatureAlgorithmXMLId);
	}

	/**
	 * This method created the CanonicalizationMethod tag like :
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 * 	}
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param signedInfoCanonicalizationMethod
	 *            the canonicalization algorithm
	 */
	private void incorporateCanonicalizationMethod(final Element parentDom, final String signedInfoCanonicalizationMethod) {
		final Element canonicalizationMethodDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.CANONICALIZATION_METHOD);
		parentDom.appendChild(canonicalizationMethodDom);		
		canonicalizationMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), signedInfoCanonicalizationMethod);
	}

	/**
	 * This method creates the ds:Reference elements in the signature.
	 */
	private void incorporateReferences() {
		ReferenceProcessor referenceProcessor = new ReferenceProcessor(params);
		referenceProcessor.incorporateReferences(signedInfoDom, params.getReferences(), getXmldsigNamespace());
	}

	/**
	 * Creates KeyInfo tag.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are
	 * included.
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:KeyInfo>
	 * 			<ds:X509Data>
	 *  			<ds:X509Certificate>
	 * 					MIIB....
	 * 				</ds:X509Certificate>
	 * 				<ds:X509Certificate>
	 * 					MIIB+...
	 * 				</ds:X509Certificate>
	 * 			</ds:X509Data>
	 * 		</ds:KeyInfo>
	 * }
	 * </pre>
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:KeyInfo>
	 * 			<ds:X509Data>
	 *  			<ds:X509Certificate>
	 * 					MIIB....
	 * 				</ds:X509Certificate>
	 * 				<ds:X509Certificate>
	 * 					MIIB+...
	 * 				</ds:X509Certificate>
	 * 			</ds:X509Data>
	 * 		</ds:KeyInfo>
	 * }
	 * </pre>
	 *
	 * @throws DSSException
	 *             if an error occurred
	 */
	protected void incorporateKeyInfo() throws DSSException {
		if (params.getSigningCertificate() == null && params.isGenerateTBSWithoutCertificate()) {
			LOG.debug("Signing certificate not available and must be added to signature DOM later");
			return;
		}

		// <ds:KeyInfo>
		final Element keyInfoElement = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.KEY_INFO);
		signatureDom.appendChild(keyInfoElement);
		if (params.isSignKeyInfo()) {
			keyInfoElement.setAttribute(XMLDSigAttribute.ID.getAttributeName(), KEYINFO_SUFFIX + deterministicId);
		}
		BaselineBCertificateSelector certSelector = new BaselineBCertificateSelector(certificateVerifier, params);
		List<CertificateToken> certificates = certSelector.getCertificates();

		if (params.isAddX509SubjectName()) {
			for (CertificateToken token : certificates) {
				// <ds:X509Data>
				final Element x509DataDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.X509_DATA);
				keyInfoElement.appendChild(x509DataDom);
				addSubjectAndCertificate(x509DataDom, token);
			}
		} else {
			// <ds:X509Data>
			final Element x509DataDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.X509_DATA);
			keyInfoElement.appendChild(x509DataDom);
			for (CertificateToken token : certificates) {
				addCertificate(x509DataDom, token);
			}
		}
		
		this.keyInfoDom = keyInfoElement;
		
	}

	/**
	 * This method creates the X509SubjectName (optional) and X509Certificate (mandatory) tags
	 *
	 * <pre>
	 * {@code
	 * 	<ds:X509SubjectName>...</X509SubjectName>
	 * 	<ds:X509Certificate>...</ds:X509Certificate>
	 * }
	 * </pre>
	 *
	 * @param x509DataDom
	 *            the parent X509Data tag
	 * @param token
	 *            the certificate to add
	 */
	private void addSubjectAndCertificate(final Element x509DataDom, final CertificateToken token) {
		DomUtils.addTextElement(documentDom, x509DataDom, getXmldsigNamespace(), XMLDSigElement.X509_SUBJECT_NAME, token.getSubject().getRFC2253());
		addCertificate(x509DataDom, token);
	}

	/**
	 * This method creates the X509Certificate tag which is mandatory
	 *
	 * <pre>
	 * {@code
	 * 	<ds:X509Certificate>...</ds:X509Certificate>
	 * }
	 * </pre>
	 *
	 * @param x509DataDom
	 *            the parent X509Data tag
	 * @param token
	 *            the certificate to add
	 */
	private void addCertificate(final Element x509DataDom, final CertificateToken token) {
		DomUtils.addTextElement(documentDom, x509DataDom, getXmldsigNamespace(), XMLDSigElement.X509_CERTIFICATE, Utils.toBase64(token.getEncoded()));
	}

	/**
	 * This method incorporates the ds:Object tags
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:Object>
	 * 			...
	 * 		</ds:Object>
	 * 		<ds:Object>
	 * 			...
	 * 		</ds:Object>
	 * }
	 * </pre>
	 *
	 */
	protected void incorporateObjects() {
		incorporateQualifyingProperties();
		incorporateSignedObjects();
		incorporateCustomObjects();
	}

	/**
	 * This method incorporates the ds:Object with xades:QualifyingProperties element
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:Object>
	 * 			<xades:QualifyingProperties>
	 * 				<xades:SignedProperties>
	 * 					...
	 * 				</xades:SignedProperties>
	 * 			</xades:QualifyingProperties>
	 * 		</ds:Object>
	 * }
	 * </pre>
	 *
	 */
	protected void incorporateQualifyingProperties() {
		if (Utils.isArrayNotEmpty(params.getSignedAdESObject())) {
			LOG.debug("Incorporating signed XAdES Object from parameter");
			if (DomUtils.isDOM(params.getSignedAdESObject())) {
				Node signedObjectDom = DomUtils.buildDOM(params.getSignedAdESObject()).getDocumentElement();
				signedObjectDom = documentDom.importNode(signedObjectDom, true);
				signatureDom.appendChild(signedObjectDom);
			} else {
				throw new IllegalArgumentException("The signed AdES Object shall represent an XML!");
			}
			return;
		}

		final Element objectDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.OBJECT);
		signatureDom.appendChild(objectDom);

		qualifyingPropertiesDom = DomUtils.addElement(documentDom, objectDom, getXadesNamespace(), getCurrentXAdESElements().getElementQualifyingProperties());
		DomUtils.addNamespaceAttribute(qualifyingPropertiesDom, getXadesNamespace());
		qualifyingPropertiesDom.setAttribute(TARGET, "#" + deterministicId);

		incorporateSignedProperties();
	}

	/**
	 * Incorporates the list of signed ds:Object elements (used for Enveloping packaging)
	 */
	protected void incorporateSignedObjects() {
		// do nothing by default
	}

	/**
	 * Incorporates a list of custom ds:Object elements within the ds:Signature element
	 */
	protected void incorporateCustomObjects() {
		if (Utils.isCollectionNotEmpty(params.getObjects())) {
			for (DSSObject object : params.getObjects()) {
				incorporateObject(object);
			}
		}
	}

	/**
	 * Incorporates the given {@code object} within the ds:Signature
	 *
	 * @param object {@link DSSObject} to incorporate
	 */
	protected void incorporateObject(DSSObject object) {
		if (object.getContent() == null) {
			throw new IllegalArgumentException("The content shall be defined inside DSSObject element! " +
					"Incorporation is not possible.");
		}

		// incorporate ds:Object dom
		final Element objectDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.OBJECT);
		signatureDom.appendChild(objectDom);

		// incorporate content
		if (DomUtils.isDOM(object.getContent())) {
			Node objectContentDom = DomUtils.buildDOM(object.getContent()).getDocumentElement();
			objectContentDom = documentDom.importNode(objectContentDom, true);
			objectDom.appendChild(objectContentDom);
		} else {
			Node textNode = documentDom.createTextNode(new String(DSSUtils.toByteArray(object.getContent())));
			objectDom.appendChild(textNode);
		}

		// incorporate Id attribute
		if (Utils.isStringNotBlank(object.getId())) {
			objectDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), object.getId());
		}

		// incorporate MimeType attribute
		if (object.getMimeType() != null) {
			objectDom.setAttribute(XMLDSigAttribute.MIME_TYPE.getAttributeName(), object.getMimeType().getMimeTypeString());
		}

		// incorporate Encoding attribute
		if (Utils.isStringNotBlank(object.getEncodingAlgorithm())) {
			objectDom.setAttribute(XMLDSigAttribute.ENCODING.getAttributeName(), object.getEncodingAlgorithm());
		}

	}

	/**
	 * This method incorporates ds:References
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI=
	"#xades-id-A43023AFEB149830C242377CC941360F">
	 *			<ds:Transforms>
	 *				<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 *			</ds:Transforms>
	 *			<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 *			<ds:DigestValue>uijX/nvuu8g10ZVEklEnYatvFe8=</ds:DigestValue>
	 *		</ds:Reference>
	 * }
	 * </pre>
	 */
	protected void incorporateReferenceSignedProperties() {
		
		final Element reference = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.REFERENCE);
		signedInfoDom.appendChild(reference);	
		reference.setAttribute(XMLDSigAttribute.TYPE.getAttributeName(), xadesPaths.getSignedPropertiesUri());
		reference.setAttribute(XMLDSigAttribute.URI.getAttributeName(), "#" + XADES_SUFFIX + deterministicId);

		final Element transforms = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.TRANSFORMS);
		reference.appendChild(transforms);
		final Element transform = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.TRANSFORM);
		transforms.appendChild(transform);
		transform.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), signedPropertiesCanonicalizationMethod);

		final DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(params);
		DSSXMLUtils.incorporateDigestMethod(reference, digestAlgorithm, getXmldsigNamespace());

		final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(signedPropertiesCanonicalizationMethod, getNodeToCanonicalize(signedPropertiesDom));
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  --> {}", signedPropertiesCanonicalizationMethod);
			LOG.trace("Canonicalized REF_2      --> {}", new String(canonicalizedBytes));
		}

		incorporateDigestValueOfReference(reference, digestAlgorithm, canonicalizedBytes);
		
	}
	
	/**
	 * Method incorporates KeyInfo ds:References.
	 *
	 * <pre>
	 * 	{@code
	 * 		<ds:Reference URI="#keyInfo-id-A43023AFEB149830C242377CC941360F">
	 *			<ds:Transforms>
	 *				<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 *			</ds:Transforms>
	 *			<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 *			<ds:DigestValue>uijX/nvuu2g10ZVEklEnYatvFe4=</ds:DigestValue>
	 *		</ds:Reference>
	 * }
	 * </pre>
	 */
	protected void incorporateReferenceKeyInfo() {
		if (!params.isSignKeyInfo()) {
			return;
		}
		
		final Element reference = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.REFERENCE);
		signedInfoDom.appendChild(reference);		
		reference.setAttribute(XMLDSigAttribute.URI.getAttributeName(), "#" + KEYINFO_SUFFIX + deterministicId);
		
		final Element transforms = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.TRANSFORMS);
		reference.appendChild(transforms);
		final Element transform = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.TRANSFORM);
		transforms.appendChild(transform);
		transform.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), keyInfoCanonicalizationMethod);
		
		final DigestAlgorithm digestAlgorithm = getReferenceDigestAlgorithmOrDefault(params);
		DSSXMLUtils.incorporateDigestMethod(reference, digestAlgorithm, getXmldsigNamespace());
		
		final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(keyInfoCanonicalizationMethod, getNodeToCanonicalize(keyInfoDom));
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method   --> {}", keyInfoCanonicalizationMethod);
			LOG.trace("Canonicalized REF_KeyInfo --> {}", new String(canonicalizedBytes));
		}

		incorporateDigestValueOfReference(reference, digestAlgorithm, canonicalizedBytes);
		
	}
	
	/**
	 * Creates the ds:DigestValue DOM object for the given {@code canonicalizedBytes}
	 *
	 * @param referenceDom - the parent element to append new DOM element to
	 * @param digestAlgorithm - {@link DigestAlgorithm} to use
	 * @param canonicalizedBytes - canonicalized byte array of the relevant reference DOM to hash
	 */
	private void incorporateDigestValueOfReference(final Element referenceDom, final DigestAlgorithm digestAlgorithm,
												   final byte[] canonicalizedBytes) {
		final Element digestValueDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(),
				XMLDSigElement.DIGEST_VALUE);
		final String base64EncodedDigestBytes = Utils.toBase64(DSSUtils.digest(digestAlgorithm, canonicalizedBytes));
		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);
		referenceDom.appendChild(digestValueDom);
	}

	/**
	 * This method incorporates the signature value.
	 */
	protected void incorporateSignatureValue() {
		signatureValueDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.SIGNATURE_VALUE);
		signatureDom.appendChild(signatureValueDom);		
		signatureValueDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), VALUE_SUFFIX + deterministicId);
	}

	/**
	 * Creates the SignedProperties DOM object element.
	 *
	 * <pre>
	 * {@code
	 * 		<SignedProperties Id="xades-ide5c549340079fe19f3f90f03354a5965">
	 * }
	 * </pre>
	 */
	protected void incorporateSignedProperties() {
		signedPropertiesDom = DomUtils.addElement(documentDom, qualifyingPropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignedProperties());
		signedPropertiesDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), XADES_SUFFIX + deterministicId);

		incorporateSignedSignatureProperties();

		incorporateSignedDataObjectProperties();
	}

	/**
	 * Creates the SignedSignatureProperties DOM object element.
	 *
	 * <pre>
	 * {@code
	 * 		<SignedSignatureProperties>
	 * 		...
	 * 		</SignedSignatureProperties>
	 * }
	 * </pre>
	 *
	 */
	protected void incorporateSignedSignatureProperties() {

		signedSignaturePropertiesDom = DomUtils.addElement(documentDom, signedPropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignedSignatureProperties());

		incorporateSigningTime();

		incorporateSigningCertificate();

		incorporatePolicy();

		incorporateSignatureProductionPlace();

		incorporateSignerRole();

	}

	/**
	 * Creates SignaturePolicyIdentifier DOM object:
	 *
	 * <pre>
	 * {@code
	 * 	<xades:SignaturePolicyIdentifier>
	 * 	    <xades:SignaturePolicyId>
	 * 	        <xades:SigPolicyId>
	 * 	            <xades:Identifier Qualifier="OIDAsURN">urn:oid:1.3.6.1.4.1.10015.1000.3.2.1</xades:Identifier>
	 * 	        </xades:SigPolicyId>
	 * 	        <xades:SigPolicyHash>
	 * 	            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
	 * 	            <ds:DigestValue>3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=</ds:DigestValue>
	 * 	        </xades:SigPolicyHash>
	 * 	        <xades:SigPolicyQualifiers>
	 * 	            <xades:SigPolicyQualifier>
	 * 	                <xades:SPURI>http://spuri.test</xades:SPURI>
	 * 	            </xades:SigPolicyQualifier>
	 * 	        </xades:SigPolicyQualifiers>
	 * 	    </xades:SignaturePolicyId>
	 * 	</xades:SignaturePolicyIdentifier>
	 * }
	 * </pre>
	 */
	private void incorporatePolicy() {

		final Policy signaturePolicy = params.bLevel().getSignaturePolicy();
		if (signaturePolicy != null) {
			final Element signaturePolicyIdentifierDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, 
					getXadesNamespace(), getCurrentXAdESElements().getElementSignaturePolicyIdentifier());

			final String signaturePolicyId = signaturePolicy.getId();
			if (Utils.isStringEmpty(signaturePolicyId)) { // implicit
				DomUtils.addElement(documentDom, signaturePolicyIdentifierDom, getXadesNamespace(),
						getCurrentXAdESElements().getElementSignaturePolicyImplied());

			} else { // explicit
				final Element signaturePolicyIdDom = DomUtils.addElement(documentDom, signaturePolicyIdentifierDom, 
						getXadesNamespace(), getCurrentXAdESElements().getElementSignaturePolicyId());
				final Element sigPolicyIdDom = DomUtils.addElement(documentDom, signaturePolicyIdDom, 
						getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyId());

				final Element identifierDom = DomUtils.addTextElement(documentDom, sigPolicyIdDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementIdentifier(), signaturePolicyId);

				final ObjectIdentifierQualifier qualifier = signaturePolicy.getQualifier();
				if (qualifier != null) {
					identifierDom.setAttribute(XAdES132Attribute.QUALIFIER.getAttributeName(), qualifier.getValue());
				}

				final String description = signaturePolicy.getDescription();
				if (Utils.isStringNotEmpty(description)) {
					DomUtils.addTextElement(documentDom, sigPolicyIdDom, getXadesNamespace(),
							getCurrentXAdESElements().getElementDescription(), description);
				}

				final String[] documentationReferences = signaturePolicy.getDocumentationReferences();
				if (Utils.isArrayNotEmpty(documentationReferences)) {
					incorporateDocumentationReferences(sigPolicyIdDom, documentationReferences);
				}

				if (signaturePolicy instanceof XmlPolicyWithTransforms) {
					final XmlPolicyWithTransforms xmlPolicy = (XmlPolicyWithTransforms) signaturePolicy;
					DSSXMLUtils.incorporateTransforms(signaturePolicyIdDom, xmlPolicy.getTransforms(), getXmldsigNamespace());
				}

				if (signaturePolicy.getDigestAlgorithm() != null && signaturePolicy.getDigestValue() != null) {
					final Element sigPolicyHashDom = DomUtils.addElement(documentDom, signaturePolicyIdDom,
							getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyHash());

					final DigestAlgorithm digestAlgorithm = signaturePolicy.getDigestAlgorithm();
					incorporateDigestMethod(sigPolicyHashDom, digestAlgorithm);

					final byte[] hashValue = signaturePolicy.getDigestValue();
					final String base64EncodedHashValue = Utils.toBase64(hashValue);
					incorporateDigestValue(sigPolicyHashDom, base64EncodedHashValue);
				}

				if (signaturePolicy.isSPQualifierPresent()) {
					incorporateSigPolicyQualifiers(signaturePolicyIdDom, signaturePolicy);
				}
			}
		}
	}

	/**
	 * Creates SigPolicyQualifiers DOM object:
	 *
	 * <pre>
	 * {@code
	 * 	<xades:SigPolicyQualifiers>
	 * 	    <xades:SigPolicyQualifier>
	 * 	        <xades:SPURI>http://signinghubbeta.cloudapp.net:7777/adss/policy/sample_sig_policy_document.txt</xades:SPURI>
	 * 	    </xades:SigPolicyQualifier>
	 * 	    <xades:SigPolicyQualifier>
	 * 	        <xades:SPUserNotice>
	 * 	            <xades:ExplicitText>This is a test policy</xades:ExplicitText>
	 * 	        </xades:SPUserNotice>
	 * 	    </xades:SigPolicyQualifier>
	 * 	</xades:SigPolicyQualifiers>
	 * }
	 * </pre>
	 */
	private void incorporateSigPolicyQualifiers(Element signaturePolicyIdDom, Policy signaturePolicy) {
		final Element sigPolicyQualifiers = DomUtils.addElement(documentDom, signaturePolicyIdDom,
				getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyQualifiers());

		final String spUri = signaturePolicy.getSpuri();
		if (Utils.isStringNotEmpty(spUri)) {
			final Element sigPolicyQualifier = DomUtils.addElement(documentDom, sigPolicyQualifiers,
					getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyQualifier());
			DomUtils.addTextElement(documentDom, sigPolicyQualifier, getXadesNamespace(),
					getCurrentXAdESElements().getElementSPURI(), spUri);
		}

		final UserNotice userNotice = signaturePolicy.getUserNotice();
		if (userNotice != null && !userNotice.isEmpty()) {
			DSSUtils.assertSPUserNoticeConfigurationValid(userNotice);

			final Element sigPolicyQualifier = DomUtils.addElement(documentDom, sigPolicyQualifiers,
					getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyQualifier());
			final Element spUserNotice = DomUtils.addElement(documentDom, sigPolicyQualifier,
					getXadesNamespace(), getCurrentXAdESElements().getElementSPUserNotice());

			final String organization = userNotice.getOrganization();
			final int[] noticeNumbers = userNotice.getNoticeNumbers();
			if (Utils.isStringNotEmpty(organization) && noticeNumbers != null && noticeNumbers.length > 0) {
				final Element noticeRef = DomUtils.addElement(documentDom, spUserNotice,
						getXadesNamespace(), getCurrentXAdESElements().getElementNoticeRef());
				DomUtils.addTextElement(documentDom, noticeRef, getXadesNamespace(),
						getCurrentXAdESElements().getElementOrganization(), organization);

				final Element noticeNumbersElement = DomUtils.addElement(documentDom, noticeRef,
						getXadesNamespace(), getCurrentXAdESElements().getElementNoticeNumbers());
				for (int number : noticeNumbers) {
					DomUtils.addTextElement(documentDom, noticeNumbersElement, getXadesNamespace(),
							getCurrentXAdESElements().getElementint(), String.valueOf(number));
				}
			}

			final String explicitText = userNotice.getExplicitText();
			if (Utils.isStringNotEmpty(explicitText)) {
				DomUtils.addTextElement(documentDom, spUserNotice, getXadesNamespace(),
						getCurrentXAdESElements().getElementExplicitText(), explicitText);
			}
		}

		final SpDocSpecification spDocSpecification = signaturePolicy.getSpDocSpecification();
		if (spDocSpecification != null && Utils.isStringNotEmpty(spDocSpecification.getId())) {

			final Element sigPolicyQualifier = DomUtils.addElement(documentDom, sigPolicyQualifiers,
					getXadesNamespace(), getCurrentXAdESElements().getElementSigPolicyQualifier());
			incorporateSPDocSpecification(sigPolicyQualifier, spDocSpecification);

		}
	}

	/**
	 * Creates SigningTime DOM object element like :
	 *
	 * <pre>
	 * 	{@code
	 * 		<SigningTime>2013-11-23T11:22:52Z</SigningTime>
	 * 	}
	 * </pre>
	 */
	private void incorporateSigningTime() {
		final Date signingDate = params.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
		final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();

		final Element signingTimeDom = DomUtils.createElementNS(documentDom, getXadesNamespace(), getCurrentXAdESElements().getElementSigningTime());
		signedSignaturePropertiesDom.appendChild(signingTimeDom);
		final Text textNode = documentDom.createTextNode(xmlSigningTime);
		signingTimeDom.appendChild(textNode);
	}

	/**
	 * Creates SigningCertificate(V2) building block DOM object:
	 *
	 * <pre>
	 * {@code
	 * 	<SigningCertificate>
	 * 		<Cert>
	 * 			<CertDigest>
	 * 				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 * 				<ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * 			</CertDigest>
	 * 			<IssuerSerial>
	 * 				<ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName>
	 * 				<ds:X509SerialNumber>4</ds:X509SerialNumber>
	 *			</IssuerSerial>
	 *		</Cert>
	 * 	</SigningCertificate>
	 * }
	 * </pre>
	 */
	private void incorporateSigningCertificate() {
		if (params.getSigningCertificate() == null && params.isGenerateTBSWithoutCertificate()) {
			return;
		}

		final Set<CertificateToken> certificates = new HashSet<>();
		certificates.add(params.getSigningCertificate());

		if (params.isEn319132()) {
			incorporateSigningCertificateV2(certificates);
		} else {
			incorporateSigningCertificateV1(certificates);
		}
	}

	private void incorporateSigningCertificateV1(Set<CertificateToken> certificates) {
		Element signingCertificateDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, getXadesNamespace(),
				getCurrentXAdESElements().getElementSigningCertificate());

		DigestAlgorithm signingCertificateDigestMethod = params.getSigningCertificateDigestMethod();
		for (final CertificateToken certificate : certificates) {
			incorporateCert(signingCertificateDom, certificate, signingCertificateDigestMethod);
		}
	}

	private void incorporateSigningCertificateV2(Set<CertificateToken> certificates) {
		Element signingCertificateDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, getXadesNamespace(),
				getCurrentXAdESElements().getElementSigningCertificateV2());

		DigestAlgorithm signingCertificateDigestMethod = params.getSigningCertificateDigestMethod();
		for (final CertificateToken certificate : certificates) {
			incorporateCert(signingCertificateDom, certificate, signingCertificateDigestMethod);
		}
	}

	/**
	 * This method incorporates the SignedDataObjectProperties DOM element like :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<SignedDataObjectProperties> ...
	 * 			<DataObjectFormat>
	 * 				...
	 *			</DataObjectFormat>
	 *          <CommitmentTypeIndication>
	 *              ...
	 *          </CommitmentTypeIndication>
	 *          <AllDataObjectsTimeStamp>
	 *              ...
	 *          </AllDataObjectsTimeStamp>
	 *          <IndividualDataObjectsTimeStamp>
	 *              ...
	 *          </IndividualDataObjectsTimeStamp>
	 *		</SignedDataObjectProperties>
	 * 	}
	 * </pre>
	 */
	private void incorporateSignedDataObjectProperties() {
		
		incorporateDataObjectFormat();
		incorporateCommitmentTypeIndications();
		incorporateContentTimestamps();
	}
	
	private Element getSignedDataObjectPropertiesDom() {
		/*
		 * 4.3.5 The SignedDataObjectProperties container 
		 * 
		 * A XAdES signature shall not incorporate an empty SignedDataObjectProperties element.
		 */
		if (signedDataObjectPropertiesDom == null) {
			signedDataObjectPropertiesDom = DomUtils.addElement(documentDom, signedPropertiesDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementSignedDataObjectProperties());
		}
		return signedDataObjectPropertiesDom;
	}
	
	/**
	 * This method incorporates the SignedDataObjectProperties DOM element like :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<DataObjectFormat ObjectReference="#detached-ref-id">
	 * 			<MimeType>text/plain</MimeType>
	 * 			...
	 *		</DataObjectFormat>
	 * 	}
	 * </pre>
	 */
	private void incorporateDataObjectFormat() {
		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {
			
			if (xadesPaths.getCounterSignatureUri().equals(reference.getType())) {
				/*
				 * 6.3 Requirements on XAdES signature's elements, qualifying properties and services
				 * 
				 * k) Requirement for DataObjectFormat. One DataObjectFormat shall be generated for each signed data
				 * object, except the SignedProperties element, and except if the signature is a baseline signature
				 * countersigning a signature. If the signature is a baseline signature countersigning another signature, and if it
				 * only signs its own signed properties and the countersigned signature, then it shall not include any
				 * DataObjectFormat signed property. If the signature is a baseline signature countersigning another signature
				 * and if it signs its own signed properties, the countersigned signature, and other data object(s), then it shall
				 * include one DataObjectFormat signed property for each of these other signed data object(s) aforementioned. 
				 */
				continue;
			}

			final String dataObjectFormatObjectReference = "#" + reference.getId();

			final Element dataObjectFormatDom = DomUtils.addElement(documentDom, getSignedDataObjectPropertiesDom(), 
					getXadesNamespace(), getCurrentXAdESElements().getElementDataObjectFormat());
			dataObjectFormatDom.setAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName(), dataObjectFormatObjectReference);

			final Element mimeTypeDom = DomUtils.addElement(documentDom, dataObjectFormatDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementMimeType());
			MimeType dataObjectFormatMimeType = getReferenceMimeType(reference);
			DomUtils.setTextNode(documentDom, mimeTypeDom, dataObjectFormatMimeType.getMimeTypeString());
		}
	}

	/**
	 * This method returns the mimetype of the given reference
	 *
	 * @param reference
	 *            the reference to compute
	 * @return the {@code MimeType} of the reference or the default value {@code MimeType.BINARY}
	 */
	private MimeType getReferenceMimeType(final DSSReference reference) {
		MimeType dataObjectFormatMimeType = MimeType.BINARY;
		DSSDocument content = reference.getContents();
		if (content != null && content.getMimeType() != null) {
			dataObjectFormatMimeType = content.getMimeType();
		}
		return dataObjectFormatMimeType;
	}

	/**
	 * This method incorporate the content-timestamps within the signature being created.
	 */
	private void incorporateContentTimestamps() {

		final List<TimestampToken> contentTimestamps = params.getContentTimestamps();
		if (contentTimestamps == null) {
			return;
		}

		for (final TimestampToken contentTimestamp : contentTimestamps) {
			final String timestampId = TIMESTAMP_SUFFIX + contentTimestamp.getDSSIdAsString();
			final TimestampType timeStampType = contentTimestamp.getTimeStampType();
			if (TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {
				Element allDataObjectsTimestampDom = DomUtils.addElement(documentDom, getSignedDataObjectPropertiesDom(), 
						getXadesNamespace(), getCurrentXAdESElements().getElementAllDataObjectsTimeStamp());
				allDataObjectsTimestampDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), timestampId);
				addTimestamp(allDataObjectsTimestampDom, contentTimestamp);
			} else if (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {
				Element individualDataObjectsTimestampDom = DomUtils.addElement(documentDom, getSignedDataObjectPropertiesDom(), 
						getXadesNamespace(), getCurrentXAdESElements().getElementIndividualDataObjectsTimeStamp());
				individualDataObjectsTimestampDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), timestampId);
				addTimestamp(individualDataObjectsTimestampDom, contentTimestamp);
			} else {
				throw new UnsupportedOperationException("Only types ALL_DATA_OBJECTS_TIMESTAMP and INDIVIDUAL_DATA_OBJECTS_TIMESTAMP are allowed");
			}
		}
	}

	/**
	 * This method incorporates the signer claimed roleType into signed signature properties.
	 */
	private void incorporateSignerRole() {

		final List<String> claimedSignerRoles = params.bLevel().getClaimedSignerRoles();
		final List<String> signedAssertions = params.bLevel().getSignedAssertions();

		Element signerRoleDom = null;
		if (claimedSignerRoles != null) {

			if (params.isEn319132()) {
				signerRoleDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignerRoleV2());
			} else {
				signerRoleDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignerRole());
			}

			if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
				final Element claimedRolesDom = DomUtils.addElement(documentDom, signerRoleDom, getXadesNamespace(), getCurrentXAdESElements().getElementClaimedRoles());
				addRoles(claimedSignerRoles, claimedRolesDom, getCurrentXAdESElements().getElementClaimedRole());
			}

		}
		if (signedAssertions != null && params.isEn319132()) {

			if (signerRoleDom == null){
				signerRoleDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignerRoleV2());
			}
 
			if (Utils.isCollectionNotEmpty(signedAssertions)) {
				final Element signedAssertionsDom = DomUtils.addElement(documentDom, signerRoleDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignedAssertions());
				addAssertions(signedAssertions, signedAssertionsDom);
			}
		}

	}

	private void addRoles(final List<String> signerRoles, final Element rolesDom, final DSSElement roleType) {

		for (final String signerRole : signerRoles) {

			final Element roleDom = DomUtils.addElement(documentDom, rolesDom, getXadesNamespace(), roleType);
			DomUtils.setTextNode(documentDom, roleDom, signerRole);
		}
	}

	private void incorporateSignatureProductionPlace() {

		final SignerLocation signatureProductionPlace = params.bLevel().getSignerLocation();
		if (signatureProductionPlace != null && !signatureProductionPlace.isEmpty()) {

			final Element signatureProductionPlaceDom;
			if (params.isEn319132()) {
				signatureProductionPlaceDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, 
						getXadesNamespace(), getCurrentXAdESElements().getElementSignatureProductionPlaceV2());
			} else {
				signatureProductionPlaceDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, 
						getXadesNamespace(), getCurrentXAdESElements().getElementSignatureProductionPlace());
			}

			final String city = signatureProductionPlace.getLocality();
			if (city != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, getXadesNamespace(), getCurrentXAdESElements().getElementCity(), city);
			}

			if (params.isEn319132()) {
				final String streetAddress = signatureProductionPlace.getStreetAddress();
				if (streetAddress != null) {
					DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, getXadesNamespace(),
							getCurrentXAdESElements().getElementStreetAddress(), streetAddress);
				}
			}

			final String stateOrProvince = signatureProductionPlace.getStateOrProvince();
			if (stateOrProvince != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, getXadesNamespace(),
						getCurrentXAdESElements().getElementStateOrProvince(), stateOrProvince);
			}

			final String postalCode = signatureProductionPlace.getPostalCode();
			if (postalCode != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, getXadesNamespace(),
						getCurrentXAdESElements().getElementPostalCode(), postalCode);
			}

			final String country = signatureProductionPlace.getCountry();
			if (country != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, getXadesNamespace(),
						getCurrentXAdESElements().getElementCountryName(), country);
			}
		}
	}

	/**
	 * Below follows the schema definition for this element.
	 *
	 * <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
	 * <xsd:complexType name="CommitmentTypeIndicationType">
	 * ...<xsd:sequence>
	 * ......<xsd:element name="CommitmentTypeId" type="ObjectIdentifierType"/>
	 * ......<xsd:choice>
	 * .........<xsd:element name="ObjectReference" type="xsd:anyURI" maxOccurs="unbounded"/>
	 * .........<xsd:element name="AllSignedDataObjects"/>
	 * ......</xsd:choice>
	 * ......<xsd:element name="CommitmentTypeQualifiers" type="CommitmentTypeQualifiersListType" minOccurs="0"/>
	 * ...</xsd:sequence>
	 * </xsd:complexType>
	 * 
	 * <xsd:complexType name="CommitmentTypeQualifiersListType">
	 * ......<xsd:sequence>
	 * .........<xsd:element name="CommitmentTypeQualifier"* type="AnyType" minOccurs="0" maxOccurs="unbounded"/>
	 * ......</xsd:sequence>
	 * </xsd:complexType
	 */
	private void incorporateCommitmentTypeIndications() {

		List<CommitmentType> commitmentTypeIndications = params.bLevel().getCommitmentTypeIndications();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {

			for (final CommitmentType commitmentTypeIndication : commitmentTypeIndications) {
				final Element commitmentTypeIndicationDom = DomUtils.addElement(documentDom, getSignedDataObjectPropertiesDom(), 
						getXadesNamespace(), getCurrentXAdESElements().getElementCommitmentTypeIndication());

				final Element commitmentTypeIdDom = DomUtils.addElement(documentDom, commitmentTypeIndicationDom, 
						getXadesNamespace(), getCurrentXAdESElements().getElementCommitmentTypeId());

				if (commitmentTypeIndication.getUri() == null) {
					throw new IllegalArgumentException("The commitmentTypeIndication URI must be defined for XAdES creation!");
				}
				
				Element identifierDom = DomUtils.addTextElement(documentDom, commitmentTypeIdDom, getXadesNamespace(), 
						getCurrentXAdESElements().getElementIdentifier(), commitmentTypeIndication.getUri());
				
				ObjectIdentifierQualifier qualifier = commitmentTypeIndication.getQualifier();
				if (qualifier != null) {
					identifierDom.setAttribute(XAdES132Attribute.QUALIFIER.getAttributeName(), qualifier.getValue());
				}
				
				String description = commitmentTypeIndication.getDescription();
				if (description != null) {
					DomUtils.addTextElement(documentDom, commitmentTypeIdDom, getXadesNamespace(), getCurrentXAdESElements().getElementDescription(),
							description);
				}
				
				String[] documentationReferences = commitmentTypeIndication.getDocumentationReferences();
				if (Utils.isArrayNotEmpty(documentationReferences)) {
					incorporateDocumentationReferences(commitmentTypeIdDom, documentationReferences);
				}
				
				// final Element objectReferenceDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom,
				// XADES, "ObjectReference");
				// or
				DomUtils.addElement(documentDom, commitmentTypeIndicationDom, getXadesNamespace(), getCurrentXAdESElements().getElementAllSignedDataObjects());

				// final Element commitmentTypeQualifiersDom = DSSXMLUtils.addElement(documentDom,
				// commitmentTypeIndicationDom, XADES, "CommitmentTypeQualifiers");
			}
		}
	}
	
	private void incorporateDocumentationReferences(Element parentElement, String[] documentationReferences) {
		final Element documentReferencesDom = DomUtils.addElement(documentDom, parentElement, 
				getXadesNamespace(), getCurrentXAdESElements().getElementDocumentationReferences());
		for (String ref : documentationReferences) {
			DomUtils.addTextElement(documentDom, documentReferencesDom, getXadesNamespace(), 
					getCurrentXAdESElements().getElementDocumentationReference(), ref);
		}
	}

	/**
	 * Adds signature value to the signature and returns XML signature (InMemoryDocument)
	 *
	 * @param signatureValue byte array
	 * @return {@link DSSDocument} representing the signature
	 */
	@Override
	public DSSDocument signDocument(final byte[] signatureValue) {
		if (!built) {
			build();
		}

		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final byte[] signatureValueBytes = DSSASN1Utils.ensurePlainSignatureValue(encryptionAlgorithm, signatureValue);
		final String signatureValueBase64Encoded = Utils.toBase64(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);
		return createXmlDocument();
	}

	/**
	 * Adds the content of a timestamp into a given timestamp element
	 *
	 * @param timestampElement {@link Element}
	 * @param token {@link TimestampToken}
	 */
	protected void addTimestamp(final Element timestampElement, final TimestampToken token) {

		// List<TimestampInclude> includes, String canonicalizationMethod, TimestampToken encapsulatedTimestamp) {
		// add includes: URI + referencedData = "true"
		// add canonicalizationMethod: Algorithm
		// add encapsulatedTimestamp: Encoding, Id, while its textContent is the base64 encoding of the data to digest
		final List<TimestampInclude> includes = token.getTimestampIncludes();
		if (includes != null) {

			for (final TimestampInclude include : includes) {

				final Element timestampIncludeElement = DomUtils.createElementNS(documentDom, getXadesNamespace(), getCurrentXAdESElements().getElementInclude());
				String uri = include.getURI();
				if (!uri.startsWith("#")) {
					uri = "#" + uri;
				}
				timestampIncludeElement.setAttribute(URI, uri);
				timestampIncludeElement.setAttribute(REFERENCED_DATA, "true");
				timestampElement.appendChild(timestampIncludeElement);
			}
		}

		String canonicalizationMethod = token.getCanonicalizationMethod();
		if (Utils.isStringNotEmpty(canonicalizationMethod)) {
			final Element canonicalizationMethodElement = DomUtils.createElementNS(documentDom, getXmldsigNamespace(),
					XMLDSigElement.CANONICALIZATION_METHOD);
			canonicalizationMethodElement.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(),
					canonicalizationMethod);
			timestampElement.appendChild(canonicalizationMethodElement);
		} else {
			throw new IllegalArgumentException("Unable to create a timestamp with empty canonicalization method. "
					+ "See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.");
		}

		Element encapsulatedTimestampElement = DomUtils.createElementNS(documentDom, getXadesNamespace(), getCurrentXAdESElements().getElementEncapsulatedTimeStamp());
		encapsulatedTimestampElement.setTextContent(Utils.toBase64(token.getEncoded()));

		timestampElement.appendChild(encapsulatedTimestampElement);
	}

	/**
	 * Returns a node to be canonicalized (applies indents if required)
	 *
	 * @param node {@link Node}
	 * @return {@link Node}
	 */
	protected Node getNodeToCanonicalize(Node node) {
		if (params.isPrettyPrint()) {
			return DSSXMLUtils.getIndentedNode(documentDom, node);
		}
		return node;
	}
	
	@Override
	protected void alignNodes() {
		if (unsignedSignaturePropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(unsignedSignaturePropertiesDom);
		}
		if (qualifyingPropertiesDom != null) {
			DSSXMLUtils.alignChildrenIndents(qualifyingPropertiesDom);
		}
	}
	
	private void addAssertions(final List<String> signedAssertions, final Element rolesDom) {
		for (final String signedAssertion : signedAssertions) {
			final Element roleDom = DomUtils.addElement(documentDom, rolesDom, getXadesNamespace(), getCurrentXAdESElements().getElementSignedAssertion());			
			Document samlAssertion = DomUtils.buildDOM(signedAssertion);
			Element docEl = samlAssertion.getDocumentElement();
			Node node = documentDom.importNode(docEl, true);
			roleDom.appendChild(node);
		}
	}

}
