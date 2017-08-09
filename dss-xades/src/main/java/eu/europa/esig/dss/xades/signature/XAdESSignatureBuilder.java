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

import static eu.europa.esig.dss.XAdESNamespaces.XAdES;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.datatype.XMLGregorianCalendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.TimestampInclude;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.SignatureBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

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
	protected DSSDocument detachedDocument;

	protected String signedInfoCanonicalizationMethod;
	protected String signedPropertiesCanonicalizationMethod;

	protected String deterministicId;

	/*
	 * This variable represents the current DOM signature object.
	 */
	protected Element signatureDom;

	protected Element signedInfoDom;
	protected Element signatureValueDom;
	protected Element qualifyingPropertiesDom;
	protected Element signedPropertiesDom;
	protected Element signedSignaturePropertiesDom;
	protected Element signedDataObjectPropertiesDom;
	protected Element unsignedSignaturePropertiesDom;

	/**
	 * Creates the signature according to the packaging
	 *
	 * @param params
	 *            The set of parameters relating to the structure and process of the creation or extension of the
	 *            electronic signature.
	 * @param document
	 *            The original document to sign.
	 * @param certificateVerifier
	 * @return
	 */
	public static XAdESSignatureBuilder getSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument document,
			final CertificateVerifier certificateVerifier) {

		switch (params.getSignaturePackaging()) {
		case ENVELOPED:
			return new EnvelopedSignatureBuilder(params, document, certificateVerifier);
		case ENVELOPING:
			return new EnvelopingSignatureBuilder(params, document, certificateVerifier);
		case DETACHED:
			return new DetachedSignatureBuilder(params, document, certificateVerifier);
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
	 * @param detachedDocument
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public XAdESSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument detachedDocument, final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		this.params = params;
		this.detachedDocument = detachedDocument;
	}

	protected void setCanonicalizationMethods(final XAdESSignatureParameters params, final String canonicalizationMethod) {

		final String signedInfoCanonicalizationMethod_ = params.getSignedInfoCanonicalizationMethod();
		if (Utils.isStringNotBlank(signedInfoCanonicalizationMethod_)) {
			signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod_;
		} else {
			signedInfoCanonicalizationMethod = canonicalizationMethod;
		}
		final String signedPropertiesCanonicalizationMethod_ = params.getSignedPropertiesCanonicalizationMethod();
		if (Utils.isStringNotBlank(signedPropertiesCanonicalizationMethod_)) {
			signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod_;
		} else {
			signedPropertiesCanonicalizationMethod = canonicalizationMethod;
		}
	}

	/**
	 * This is the main method which is called to build the XML signature
	 *
	 * @return A byte array is returned with XML that represents the canonicalized <ds:SignedInfo> segment of signature.
	 *         This data are used to define the <ds:SignatureValue>
	 *         element.
	 * @throws DSSException
	 */
	public byte[] build() throws DSSException {

		documentDom = buildRootDocumentDom();

		deterministicId = params.getDeterministicId();

		final List<DSSReference> references = params.getReferences();
		if (Utils.isCollectionEmpty(references)) {
			final List<DSSReference> defaultReferences = createDefaultReferences();
			// The SignatureParameters object is updated with the default references.
			params.setReferences(defaultReferences);
		}

		incorporateSignatureDom();

		incorporateSignedInfo();

		incorporateSignatureValue();

		incorporateKeyInfo();

		incorporateObject();

		/**
		 * We create <ds:Reference> segment only now, because we need first to define the SignedProperties segment to
		 * calculate the digest of references.
		 */
		incorporateReferences();
		incorporateReferenceSignedProperties();

		// Preparation of SignedInfo
		byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, signedInfoDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignedInfo         --> {}", new String(canonicalizedSignedInfo));
			final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedSignedInfo);
			LOG.trace("Canonicalized SignedInfo SHA256  --> {}", Utils.toBase64(digest));
		}
		built = true;
		return canonicalizedSignedInfo;
	}

	protected Document buildRootDocumentDom() {
		return DomUtils.buildDOM();
	}

	/**
	 * This method creates a new instance of Signature element.
	 */
	public void incorporateSignatureDom() {
		signatureDom = documentDom.createElementNS(XMLNS, DS_SIGNATURE);
		signatureDom.setAttribute(XMLNS_DS, XMLNS);
		signatureDom.setAttribute(ID, deterministicId);

		final Node parentNodeOfSignature = getParentNodeOfSignature();
		parentNodeOfSignature.appendChild(signatureDom);
	}

	protected Node getParentNodeOfSignature() {
		return documentDom;
	}

	public void incorporateSignedInfo() {

		// <ds:SignedInfo>
		signedInfoDom = DomUtils.addElement(documentDom, signatureDom, XMLNS, DS_SIGNED_INFO);
		incorporateCanonicalizationMethod(signedInfoDom, signedInfoCanonicalizationMethod);

		// <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
		final Element signatureMethod = DomUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_SIGNATURE_METHOD);
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		final String signatureAlgorithmXMLId = signatureAlgorithm.getXMLId();
		signatureMethod.setAttribute(ALGORITHM, signatureAlgorithmXMLId);
	}

	private void incorporateCanonicalizationMethod(final Element parentDom, final String signedInfoCanonicalizationMethod) {

		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = DomUtils.addElement(documentDom, parentDom, XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodDom.setAttribute(ALGORITHM, signedInfoCanonicalizationMethod);
	}

	/**
	 * This method creates the first reference (this is a reference to the file to sign) which is specific for each form
	 * of signature. Here, the value of the URI is the name of the file to sign or if the information is not available
	 * the URI will use the default value: "detached-file".
	 */
	private void incorporateReferences() {
		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {
			incorporateReference(reference);
		}
	}

	/**
	 * Creates KeyInfoType JAXB object.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are
	 * included.
	 *
	 * @throws DSSException
	 */
	protected void incorporateKeyInfo() throws DSSException {

		// <ds:KeyInfo>
		final Element keyInfoDom = DomUtils.addElement(documentDom, signatureDom, XMLNS, DS_KEY_INFO);
		// <ds:X509Data>
		final Element x509DataDom = DomUtils.addElement(documentDom, keyInfoDom, XMLNS, DS_X509_DATA);

		BaselineBCertificateSelector certSelector = new BaselineBCertificateSelector(certificateVerifier, params);
		List<CertificateToken> certificates = certSelector.getCertificates();
		for (CertificateToken token : certificates) {
			addCertificate(x509DataDom, token);
		}
	}

	private void addCertificate(final Element x509DataDom, final CertificateToken token) {
		// <ds:X509Certificate>...</ds:X509Certificate>
		DomUtils.addTextElement(documentDom, x509DataDom, XMLNS, DS_X509_CERTIFICATE, Utils.toBase64(token.getEncoded()));
	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateObject() throws DSSException {

		// <ds:Object>
		final Element objectDom = DomUtils.addElement(documentDom, signatureDom, XMLNS, DS_OBJECT);

		// <QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.3.2#"
		// Target="#sigId-ide5c549340079fe19f3f90f03354a5965">
		qualifyingPropertiesDom = DomUtils.addElement(documentDom, objectDom, XAdES, XADES_QUALIFYING_PROPERTIES);
		qualifyingPropertiesDom.setAttribute(XMLNS_XADES, XAdES);
		qualifyingPropertiesDom.setAttribute(TARGET, "#" + deterministicId);

		incorporateSignedProperties();
	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateReferenceSignedProperties() throws DSSException {

		// <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties"
		// URI="#xades-ide5c549340079fe19f3f90f03354a5965">
		final Element reference = DomUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_REFERENCE);
		reference.setAttribute(TYPE, xPathQueryHolder.XADES_SIGNED_PROPERTIES);
		reference.setAttribute(URI, "#xades-" + deterministicId);
		// <ds:Transforms>
		final Element transforms = DomUtils.addElement(documentDom, reference, XMLNS, DS_TRANSFORMS);
		// <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element transform = DomUtils.addElement(documentDom, transforms, XMLNS, DS_TRANSFORM);
		transform.setAttribute(ALGORITHM, signedPropertiesCanonicalizationMethod);
		// </ds:Transforms>

		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		incorporateDigestMethod(reference, digestAlgorithm);

		// <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
		final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(signedPropertiesCanonicalizationMethod, signedPropertiesDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  --> {}", signedPropertiesCanonicalizationMethod);
			LOG.trace("Canonicalised REF_2      --> {}", new String(canonicalizedBytes));
		}
		incorporateDigestValue(reference, digestAlgorithm, new InMemoryDocument(canonicalizedBytes));
	}

	/**
	 * This method incorporates a reference within the signedInfoDom
	 *
	 * @param dssReference
	 *            {@code DSSReference}
	 */
	private void incorporateReference(final DSSReference dssReference) {

		final Element referenceDom = DomUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_REFERENCE);
		if (dssReference.getId() != null) {
			referenceDom.setAttribute(ID, dssReference.getId());
		}
		final String uri = dssReference.getUri();
		referenceDom.setAttribute(URI, uri);
		referenceDom.setAttribute(TYPE, dssReference.getType());

		final List<DSSTransform> dssTransforms = dssReference.getTransforms();
		if (dssTransforms != null) { // Detached signature may not have transformations

			final Element transformsDom = DomUtils.addElement(documentDom, referenceDom, XMLNS, DS_TRANSFORMS);
			for (final DSSTransform dssTransform : dssTransforms) {

				final Element transformDom = DomUtils.addElement(documentDom, transformsDom, XMLNS, DS_TRANSFORM);
				createTransform(documentDom, dssTransform, transformDom);
			}
		}
		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = dssReference.getDigestMethodAlgorithm();
		incorporateDigestMethod(referenceDom, digestAlgorithm);

		final DSSDocument canonicalizedDocument = transformReference(dssReference);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Reference canonicalization method  -->" + signedInfoCanonicalizationMethod);
		}
		incorporateDigestValue(referenceDom, digestAlgorithm, canonicalizedDocument);
	}

	static void createTransform(final Document document, final DSSTransform dssTransform, final Element transformDom) {

		transformDom.setAttribute(ALGORITHM, dssTransform.getAlgorithm());

		final String elementName = dssTransform.getElementName();
		final String textContent = dssTransform.getTextContent();
		if (Utils.isStringNotBlank(elementName)) {

			final String namespace = dssTransform.getNamespace();
			DomUtils.addTextElement(document, transformDom, namespace, elementName, textContent);
		} else if (Utils.isStringNotBlank(textContent)) {

			final Document transformContentDoc = DomUtils.buildDOM(textContent);
			final Element contextDocumentElement = transformContentDoc.getDocumentElement();
			document.adoptNode(contextDocumentElement);
			transformDom.appendChild(contextDocumentElement);
		}
	}

	/**
	 * When the user does not want to create its own references (only when signing one contents) the default one are
	 * created.
	 *
	 * @return {@code List} of {@code DSSReference}
	 */
	private List<DSSReference> createDefaultReferences() {
		final List<DSSReference> references = new ArrayList<DSSReference>();
		references.add(createReference(detachedDocument, 1));
		return references;
	}

	List<DSSReference> createReferencesForDocuments(List<DSSDocument> documents) {
		List<DSSReference> references = new ArrayList<DSSReference>();
		int referenceIndex = 1;
		for (DSSDocument dssDocument : documents) {
			references.add(createReference(dssDocument, referenceIndex));
			referenceIndex++;
		}
		return references;
	}

	protected abstract DSSReference createReference(DSSDocument document, int referenceIndex);

	/**
	 * This method performs the reference transformation. Note that for the time being (4.3.0-RC) only two types of
	 * transformation are implemented: canonicalization & {@code
	 * Transforms.TRANSFORM_XPATH} and can be applied only for {@code SignaturePackaging.ENVELOPED}.
	 *
	 * @param reference
	 *            {@code DSSReference} to be transformed
	 * @return {@code DSSDocument} containing transformed reference's data
	 */
	protected abstract DSSDocument transformReference(final DSSReference reference);

	/**
	 * This method incorporates the signature value.
	 */
	protected void incorporateSignatureValue() {

		signatureValueDom = DomUtils.addElement(documentDom, signatureDom, XMLNS, DS_SIGNATURE_VALUE);
		signatureValueDom.setAttribute(ID, "value-" + deterministicId);
	}

	/**
	 * Creates the SignedProperties DOM object element.
	 *
	 * @throws DSSException
	 */
	protected void incorporateSignedProperties() throws DSSException {

		// <SignedProperties Id="xades-ide5c549340079fe19f3f90f03354a5965">
		signedPropertiesDom = DomUtils.addElement(documentDom, qualifyingPropertiesDom, XAdES, XADES_SIGNED_PROPERTIES);
		signedPropertiesDom.setAttribute(ID, "xades-" + deterministicId);

		incorporateSignedSignatureProperties();
	}

	/**
	 * Creates the SignedSignatureProperties DOM object element.
	 *
	 */
	protected void incorporateSignedSignatureProperties() {

		// <SignedSignatureProperties>
		signedSignaturePropertiesDom = DomUtils.addElement(documentDom, signedPropertiesDom, XAdES, XADES_SIGNED_SIGNATURE_PROPERTIES);

		incorporateSigningTime();

		incorporateSigningCertificate();

		incorporateSignedDataObjectProperties();

		incorporatePolicy();

		incorporateSignatureProductionPlace();

		incorporateSignerRole();

		incorporateCommitmentTypeIndications();
	}

	private void incorporatePolicy() {

		final Policy signaturePolicy = params.bLevel().getSignaturePolicy();
		if ((signaturePolicy != null)) {// && (signaturePolicy.getId() != null)) {

			final Element signaturePolicyIdentifierDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES,
					XADES_SIGNATURE_POLICY_IDENTIFIER);

			String signaturePolicyId = signaturePolicy.getId();
			if (Utils.isStringEmpty(signaturePolicyId)) { // implicit
				DomUtils.addElement(documentDom, signaturePolicyIdentifierDom, XAdES, XADES_SIGNATURE_POLICY_IMPLIED);
			} else { // explicit
				final Element signaturePolicyIdDom = DomUtils.addElement(documentDom, signaturePolicyIdentifierDom, XAdES, XADES_SIGNATURE_POLICY_ID);
				final Element sigPolicyIdDom = DomUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIG_POLICY_ID);

				Element identifierDom = DomUtils.addTextElement(documentDom, sigPolicyIdDom, XAdES, XADES_IDENTIFIER, signaturePolicyId);
				String qualifier = signaturePolicy.getQualifier();
				if (Utils.isStringNotBlank(qualifier)) {
					identifierDom.setAttribute(QUALIFIER, qualifier);
				}

				String description = signaturePolicy.getDescription();
				if (Utils.isStringNotEmpty(description)) {
					DomUtils.addTextElement(documentDom, sigPolicyIdDom, XAdES, XADES_DESCRIPTION, description);
				}

				if ((signaturePolicy.getDigestAlgorithm() != null) && (signaturePolicy.getDigestValue() != null)) {

					final Element sigPolicyHashDom = DomUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIG_POLICY_HASH);

					// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					final DigestAlgorithm digestAlgorithm = signaturePolicy.getDigestAlgorithm();
					incorporateDigestMethod(sigPolicyHashDom, digestAlgorithm);

					final byte[] hashValue = signaturePolicy.getDigestValue();
					final String bas64EncodedHashValue = Utils.toBase64(hashValue);
					DomUtils.addTextElement(documentDom, sigPolicyHashDom, XMLNS, DS_DIGEST_VALUE, bas64EncodedHashValue);
				}

				String spuri = signaturePolicy.getSpuri();
				if (Utils.isStringNotEmpty(spuri)) {
					Element sigPolicyQualifiers = DomUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIGNATURE_POLICY_QUALIFIERS);
					Element sigPolicyQualifier = DomUtils.addElement(documentDom, sigPolicyQualifiers, XAdES, XADES_SIGNATURE_POLICY_QUALIFIER);

					DomUtils.addTextElement(documentDom, sigPolicyQualifier, XAdES, XADES_SPURI, spuri);
				}
			}
		}
	}

	/**
	 * Creates SigningTime DOM object element.
	 */
	private void incorporateSigningTime() {

		final Date signingDate = params.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
		final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();

		// <SigningTime>2013-11-23T11:22:52Z</SigningTime>
		final Element signingTimeDom = documentDom.createElementNS(XAdES, XADES_SIGNING_TIME);
		signedSignaturePropertiesDom.appendChild(signingTimeDom);
		final Text textNode = documentDom.createTextNode(xmlSigningTime);
		signingTimeDom.appendChild(textNode);
	}

	/**
	 * Creates SigningCertificate building block DOM object:
	 *
	 * <SigningCertificate> <Cert> <CertDigest> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 * <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * </CertDigest> <IssuerSerial> <ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName>
	 * <ds:X509SerialNumber>4</ds:X509SerialNumber> </IssuerSerial> </Cert>
	 * </SigningCertificate>
	 */
	private void incorporateSigningCertificate() {
		final Set<CertificateToken> certificates = new HashSet<CertificateToken>();
		certificates.add(params.getSigningCertificate());

		if (params.isEn319132()) {
			incorporateSigningCertificateV2(certificates);
		} else {
			incorporateSigningCertificateV1(certificates);
		}
	}

	private void incorporateSigningCertificateV1(Set<CertificateToken> certificates) {
		Element signingCertificateDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XAdESNamespaces.getXADES_SIGNING_CERTIFICATE());

		for (final CertificateToken certificate : certificates) {
			final Element certDom = incorporateCert(signingCertificateDom, certificate);
			incorporateIssuerV1(certDom, certificate);
		}
	}

	private void incorporateSigningCertificateV2(Set<CertificateToken> certificates) {
		Element signingCertificateDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES,
				XAdESNamespaces.getXADES_SIGNING_CERTIFICATE_V2());

		for (final CertificateToken certificate : certificates) {
			final Element certDom = incorporateCert(signingCertificateDom, certificate);
			incorporateIssuerV2(certDom, certificate);
		}
	}

	/**
	 * This method incorporates the SignedDataObjectProperties DOM element <SignedDataObjectProperties> ...
	 * <DataObjectFormat ObjectReference="#detached-ref-id">
	 * ......<MimeType>text/plain</MimeType> ...</DataObjectFormat> </SignedDataObjectProperties>
	 */
	private void incorporateSignedDataObjectProperties() {

		signedDataObjectPropertiesDom = DomUtils.addElement(documentDom, signedPropertiesDom, XAdES, XADES_SIGNED_DATA_OBJECT_PROPERTIES);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			final String dataObjectFormatObjectReference = "#" + reference.getId();

			final Element dataObjectFormatDom = DomUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_DATA_OBJECT_FORMAT);
			dataObjectFormatDom.setAttribute(OBJECT_REFERENCE, dataObjectFormatObjectReference);

			final Element mimeTypeDom = DomUtils.addElement(documentDom, dataObjectFormatDom, XAdES, XADES_MIME_TYPE);
			MimeType dataObjectFormatMimeType = getReferenceMimeType(reference);
			DomUtils.setTextNode(documentDom, mimeTypeDom, dataObjectFormatMimeType.getMimeTypeString());
		}

		incorporateContentTimestamps();
	}

	/**
	 * @param reference
	 *            the reference to compute
	 * @return the {@code MimeType} of the reference or the default value {@code MimeType.BINARY}
	 */
	private MimeType getReferenceMimeType(final DSSReference reference) {

		MimeType dataObjectFormatMimeType = reference.getContents().getMimeType();
		if (dataObjectFormatMimeType == null) {
			dataObjectFormatMimeType = MimeType.BINARY;
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
		Element allDataObjectsTimestampDom = null;
		Element individualDataObjectsTimestampDom = null;
		for (final TimestampToken contentTimestamp : contentTimestamps) {

			final TimestampType timeStampType = contentTimestamp.getTimeStampType();
			if (TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {

				if (allDataObjectsTimestampDom == null) {

					allDataObjectsTimestampDom = DomUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_ALL_DATA_OBJECTS_TIME_STAMP);
				}
				addTimestamp(allDataObjectsTimestampDom, contentTimestamp);

			} else if (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {

				if (individualDataObjectsTimestampDom == null) {

					individualDataObjectsTimestampDom = DomUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES,
							XADES_INDIVIDUAL_DATA_OBJECTS_TIME_STAMP);
				}
				addTimestamp(individualDataObjectsTimestampDom, contentTimestamp);
			}
		}
	}

	/**
	 * This method incorporates the signer claimed roleType into signed signature properties.
	 */
	private void incorporateSignerRole() {

		final List<String> claimedSignerRoles = params.bLevel().getClaimedSignerRoles();
		final List<String> certifiedSignerRoles = params.bLevel().getCertifiedSignerRoles();
		if ((claimedSignerRoles != null) || (certifiedSignerRoles != null)) {

			final Element signerRoleDom;

			if (params.isEn319132()) {
				signerRoleDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XADES_SIGNER_ROLE_V2);
			} else {
				signerRoleDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XADES_SIGNER_ROLE);
			}

			if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
				final Element claimedRolesDom = DomUtils.addElement(documentDom, signerRoleDom, XAdES, XADES_CLAIMED_ROLES);
				addRoles(claimedSignerRoles, claimedRolesDom, XADES_CLAIMED_ROLE);
			}

			if (Utils.isCollectionNotEmpty(certifiedSignerRoles)) {
				final Element certifiedRolesDom;
				if (params.isEn319132()) {
					certifiedRolesDom = DomUtils.addElement(documentDom, signerRoleDom, XAdES, XADES_CERTIFIED_ROLES_V2);
				} else {
					certifiedRolesDom = DomUtils.addElement(documentDom, signerRoleDom, XAdES, XADES_CERTIFIED_ROLES);
				}

				addRoles(certifiedSignerRoles, certifiedRolesDom, XADES_CERTIFIED_ROLE);
			}
		}

	}

	private void addRoles(final List<String> signerRoles, final Element rolesDom, final String roleType) {

		for (final String signerRole : signerRoles) {

			final Element roleDom = DomUtils.addElement(documentDom, rolesDom, XAdES, roleType);
			DomUtils.setTextNode(documentDom, roleDom, signerRole);
		}
	}

	private void incorporateSignatureProductionPlace() {

		final SignerLocation signatureProductionPlace = params.bLevel().getSignerLocation();
		if (signatureProductionPlace != null) {

			final Element signatureProductionPlaceDom;
			if (params.isEn319132()) {
				signatureProductionPlaceDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XADES_SIGNATURE_PRODUCTION_PLACE_V2);
			} else {
				signatureProductionPlaceDom = DomUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XADES_SIGNATURE_PRODUCTION_PLACE);
			}

			final String city = signatureProductionPlace.getLocality();
			if (city != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_CITY, city);
			}

			if (params.isEn319132()) {
				final String streetAddress = signatureProductionPlace.getStreet();
				if (streetAddress != null) {
					DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_STREET_ADDRESS, streetAddress);
				}
			}

			final String stateOrProvince = signatureProductionPlace.getStateOrProvince();
			if (stateOrProvince != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_STATE_OR_PROVINCE, stateOrProvince);
			}

			final String postalCode = signatureProductionPlace.getPostalCode();
			if (postalCode != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_POSTAL_CODE, postalCode);
			}

			final String country = signatureProductionPlace.getCountry();
			if (country != null) {
				DomUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_COUNTRY_NAME, country);
			}
		}
	}

	/**
	 * Below follows the schema definition for this element.
	 * <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
	 *
	 * <xsd:complexType name="CommitmentTypeIndicationType"> ...<xsd:sequence> ......
	 * <xsd:element name="CommitmentTypeId" type="ObjectIdentifierType"/> ......<xsd:choice>
	 * .........<xsd:element name="ObjectReference" type="xsd:anyURI" maxOccurs="unbounded"/> .........< xsd:element
	 * name="AllSignedDataObjects"/> ......</xsd:choice>
	 * ......<xsd:element name="CommitmentTypeQualifiers" type="CommitmentTypeQualifiersListType" minOccurs="0"/> ...
	 * </xsd:sequence> </xsd:complexType> <xsd:complexType
	 * name="CommitmentTypeQualifiersListType"> ...<xsd:sequence> ......
	 * <xsd:element name="CommitmentTypeQualifier" type="AnyType" minOccurs="0" maxOccurs="unbounded"/>
	 * ...</xsd:sequence> </xsd:complexType>
	 */
	private void incorporateCommitmentTypeIndications() {

		final List<String> commitmentTypeIndications = params.bLevel().getCommitmentTypeIndications();
		if (commitmentTypeIndications != null) {

			final Element commitmentTypeIndicationDom = DomUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES,
					XADES_COMMITMENT_TYPE_INDICATION);

			final Element commitmentTypeIdDom = DomUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdES, XADES_COMMITMENT_TYPE_ID);

			for (final String commitmentTypeIndication : commitmentTypeIndications) {
				DomUtils.addTextElement(documentDom, commitmentTypeIdDom, XAdES, XADES_IDENTIFIER, commitmentTypeIndication);
			}
			// final Element objectReferenceDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom,
			// XADES, "ObjectReference");
			// or
			DomUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdES, XADES_ALL_SIGNED_DATA_OBJECTS);

			// final Element commitmentTypeQualifiersDom = DSSXMLUtils.addElement(documentDom,
			// commitmentTypeIndicationDom, XADES, "CommitmentTypeQualifiers");
		}
	}

	/**
	 * Adds signature value to the signature and returns XML signature (InMemoryDocument)
	 *
	 * @param signatureValue
	 * @return
	 * @throws DSSException
	 */
	@Override
	public DSSDocument signDocument(final byte[] signatureValue) throws DSSException {
		if (!built) {
			build();
		}

		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final byte[] signatureValueBytes = DSSSignatureUtils.convertToXmlDSig(encryptionAlgorithm, signatureValue);
		final String signatureValueBase64Encoded = Utils.toBase64(signatureValueBytes);
		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		byte[] documentBytes = DSSXMLUtils.serializeNode(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}

	/**
	 * Adds the content of a timestamp into a given timestamp element
	 *
	 * @param timestampElement
	 */
	protected void addTimestamp(final Element timestampElement, final TimestampToken token) {

		// List<TimestampInclude> includes, String canonicalizationMethod, TimestampToken encapsulatedTimestamp) {
		// add includes: URI + referencedData = "true"
		// add canonicalizationMethod: Algorithm
		// add encapsulatedTimestamp: Encoding, Id, while its textContent is the base64 encoding of the data to digest
		final List<TimestampInclude> includes = token.getTimestampIncludes();
		if (includes != null) {

			for (final TimestampInclude include : includes) {

				final Element timestampIncludeElement = documentDom.createElementNS(XAdES, XADES_INCLUDE);
				String uri = include.getURI();
				if (!uri.startsWith("#")) {
					uri = "#" + uri;
				}
				timestampIncludeElement.setAttribute(URI, uri);
				timestampIncludeElement.setAttribute(REFERENCED_DATA, "true");
				timestampElement.appendChild(timestampIncludeElement);
			}
		}
		final Element canonicalizationMethodElement = documentDom.createElementNS(XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodElement.setAttribute(ALGORITHM, token.getCanonicalizationMethod());

		timestampElement.appendChild(canonicalizationMethodElement);

		Element encapsulatedTimestampElement = documentDom.createElementNS(XAdES, XADES_ENCAPSULATED_TIME_STAMP);
		encapsulatedTimestampElement.setTextContent(Utils.toBase64(token.getEncoded()));

		timestampElement.appendChild(encapsulatedTimestampElement);
	}
}