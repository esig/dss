/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.xades;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.TimestampInclude;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * This class implements all the necessary mechanisms to build each form of the XML signature. <p/> <p/> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public abstract class SignatureBuilder extends XAdESBuilder {

	/*
	 * Indicates if the signature was already built. (Two steps building)
	 */
	protected boolean built = false;

	/*
	 * This is the reference to the original document to sign
	 */
	protected DSSDocument originalDocument;

	protected String signedInfoCanonicalizationMethod;
	protected String reference2CanonicalizationMethod;

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

	/*
	 * The object encapsulating the Time Stamp Protocol needed to create the level -T, of the signature
     */
	protected TSPSource tspSource;

	/**
	 * Creates the signature according to the packaging
	 *
	 * @param params   The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
	 * @param document The original document to sign.
	 * @return
	 */
	public static SignatureBuilder getSignatureBuilder(final SignatureParameters params, final DSSDocument document) {

		switch (params.getSignaturePackaging()) {
			case ENVELOPED:
				return new EnvelopedSignatureBuilder(params, document);
			case ENVELOPING:
				return new EnvelopingSignatureBuilder(params, document);
			case DETACHED:
				return new DetachedSignatureBuilder(params, document);
			default:

				throw new DSSException("Unsupported packaging " + params.getSignaturePackaging());
		}
	}

	/**
	 * The default constructor for SignatureBuilder.
	 *
	 * @param params           The set of parameters relating to the structure and process of the creation or extension of the electronic signature.
	 * @param originalDocument The original document to sign.
	 */
	public SignatureBuilder(final SignatureParameters params, final DSSDocument originalDocument) {

		this.params = params;
		this.originalDocument = originalDocument;
	}

	/**
	 * This is the main method which is called to build the XML signature
	 *
	 * @return A byte array is returned with XML that represents the canonicalized <ds:SignedInfo> segment of signature. This data are used to define the <ds:SignatureValue>
	 * element.
	 * @throws DSSException
	 */
	public byte[] build() throws DSSException {

		documentDom = DSSXMLUtils.buildDOM();

		deterministicId = params.getDeterministicId();

		incorporateSignatureDom();

		incorporateSignedInfo();

		incorporateSignatureValue();

		incorporateKeyInfo();

		incorporateObject();

		/**
		 * We create <ds:Reference> segment only now, because we need first to define the SignedProperties segment to
		 * calculate the digest of references.
		 */
		incorporateReference1();
		incorporateReference2();

		// Preparation of SignedInfo
		byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, signedInfoDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignedInfo         --> {}", new String(canonicalizedSignedInfo));
		}
		built = true;
		return canonicalizedSignedInfo;
	}

	/**
	 * This method creates a new instance of Signature element.
	 */
	public void incorporateSignatureDom() {

		signatureDom = documentDom.createElementNS(XMLSignature.XMLNS, "ds:Signature");
		signatureDom.setAttribute("xmlns:ds", XMLSignature.XMLNS);
		signatureDom.setAttribute("Id", deterministicId);
		documentDom.appendChild(signatureDom);
	}

	public void incorporateSignedInfo() {

		// <ds:SignedInfo>
		signedInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLSignature.XMLNS, "ds:SignedInfo");
		incorporateCanonicalizationMethod(signedInfoDom, signedInfoCanonicalizationMethod);

		//<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
		final Element signatureMethod = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLSignature.XMLNS, "ds:SignatureMethod");
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		final String signatureAlgoXMLId = signatureAlgo.getXMLId();
		signatureMethod.setAttribute("Algorithm", signatureAlgoXMLId);
	}

	private void incorporateCanonicalizationMethod(final Element parentDom, final String signedInfoCanonicalizationMethod) {

		//<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = DSSXMLUtils.addElement(documentDom, parentDom, XMLSignature.XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodDom.setAttribute("Algorithm", signedInfoCanonicalizationMethod);
	}

	protected abstract void incorporateReference1() throws DSSException;

	/**
	 * Creates KeyInfoType JAXB object
	 *
	 * @throws DSSException
	 */
	protected void incorporateKeyInfo() throws DSSException {

		// <ds:KeyInfo>
		final Element keyInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLSignature.XMLNS, "ds:KeyInfo");
		// <ds:X509Data>
		final Element x509DataDom = DSSXMLUtils.addElement(documentDom, keyInfoDom, XMLSignature.XMLNS, "ds:X509Data");

		for (final X509Certificate x509Certificate : params.getCertificateChain()) {

			final byte[] encoded = DSSUtils.getEncoded(x509Certificate);
			final String base64Encoded = DSSUtils.base64Encode(encoded);
			// <ds:X509Certificate>...</ds:X509Certificate>
			DSSXMLUtils.addTextElement(documentDom, x509DataDom, XMLSignature.XMLNS, "ds:X509Certificate", base64Encoded);
		}
	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateObject() throws DSSException {

		// <ds:Object>
		final Element objectDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLSignature.XMLNS, "ds:Object");

		// <QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.3.2#" Target="#sigId-ide5c549340079fe19f3f90f03354a5965">
		qualifyingPropertiesDom = DSSXMLUtils.addElement(documentDom, objectDom, XAdESNamespaces.XAdES, "xades:QualifyingProperties");
		qualifyingPropertiesDom.setAttribute("xmlns:xades", XAdESNamespaces.XAdES);
		qualifyingPropertiesDom.setAttribute("Target", "#" + deterministicId);

		incorporateSignedProperties();
	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateReference2() throws DSSException {

		// <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-ide5c549340079fe19f3f90f03354a5965">
		final Element reference = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLSignature.XMLNS, "ds:Reference");
		reference.setAttribute("Type", xPathQueryHolder.XADES_SIGNED_PROPERTIES);
		reference.setAttribute("URI", "#xades-" + deterministicId);
		// <ds:Transforms>
		final Element transforms = DSSXMLUtils.addElement(documentDom, reference, XMLSignature.XMLNS, "ds:Transforms");
		// <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element transform = DSSXMLUtils.addElement(documentDom, transforms, XMLSignature.XMLNS, "ds:Transform");
		transform.setAttribute("Algorithm", reference2CanonicalizationMethod);
		// </ds:Transforms>

		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		incorporateDigestMethod(reference, digestAlgorithm);

		// <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
		final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(reference2CanonicalizationMethod, signedPropertiesDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  --> {}", signedInfoCanonicalizationMethod);
			LOG.trace("Canonicalised REF_2      --> {}", new String(canonicalizedBytes));
		}
		incorporateDigestValue(reference, digestAlgorithm, new InMemoryDocument(canonicalizedBytes));
	}

	/**
	 * This method incorporates a given list of references in the DOM
	 * @param references
	 */
	protected void incorporateReferences(List<DSSReference> references) {

		for (DSSReference reference : references) {
			incorporateReference(reference);
		}
	}

	/**
	 * This method incorporates a reference in the signedInfoDom
	 * @param reference
	 * @throws DSSException
	 */
	protected void incorporateReference(DSSReference reference) throws DSSException {

		final Element referenceDom = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLSignature.XMLNS, "ds:Reference");
		referenceDom.setAttribute("Id", reference.getId());
		referenceDom.setAttribute("URI", reference.getUri());
		referenceDom.setAttribute("Type", reference.getType());

		final Element transformsDom = DSSXMLUtils.addElement(documentDom, referenceDom, XMLSignature.XMLNS, "ds:Transforms");

		final List<DSSTransform> transforms = reference.getTransforms();
		for (final DSSTransform transform : transforms) {

			final Element transformDom = DSSXMLUtils.addElement(documentDom, transformsDom, XMLSignature.XMLNS, "ds:Transform");
			transformDom.setAttribute("Algorithm", transform.getAlgorithm());
			final String elementName = transform.getElementName();
			if (elementName != null && !elementName.isEmpty()) {

				final String namespace = transform.getNamespace();
				final String textContent = transform.getTextContent();
				DSSXMLUtils.addTextElement(documentDom, transformDom, namespace, elementName, textContent);
			}
		}
		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		incorporateDigestMethod(referenceDom, digestAlgorithm);

		// We remove existing signatures
		final Document domDoc = DSSXMLUtils.buildDOM(originalDocument);
		final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureDOM = (Element) signatureNodeList.item(ii);
			signatureDOM.getParentNode().removeChild(signatureDOM);
		}
		byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, domDoc);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  -->" + signedInfoCanonicalizationMethod);
			LOG.trace("Canonicalized REF_1      --> " + new String(canonicalizedBytes));
		}
		incorporateDigestValue(referenceDom, digestAlgorithm, new InMemoryDocument(canonicalizedBytes));
	}

	/**
	 * @return
	 */
	protected void incorporateSignatureValue() {

		signatureValueDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLSignature.XMLNS, "ds:SignatureValue");
		signatureValueDom.setAttribute("Id", "value-" + deterministicId);
	}

	/**
	 * Creates the SignedProperties DOM object element.
	 *
	 * @throws DSSException
	 */
	protected void incorporateSignedProperties() throws DSSException {

		// <SignedProperties Id="xades-ide5c549340079fe19f3f90f03354a5965">
		signedPropertiesDom = DSSXMLUtils.addElement(documentDom, qualifyingPropertiesDom, XAdESNamespaces.XAdES, "xades:SignedProperties");
		signedPropertiesDom.setAttribute("Id", "xades-" + deterministicId);

		incorporateSignedSignatureProperties();
	}

	/**
	 * Creates the SignedSignatureProperties DOM object element.
	 *
	 * @throws DSSException
	 */
	protected void incorporateSignedSignatureProperties() throws DSSException {

		// <SignedSignatureProperties>
		signedSignaturePropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdESNamespaces.XAdES, "xades:SignedSignatureProperties");

		incorporateSigningTime();

		incorporateSigningCertificate();

		incorporateSignedDataObjectProperties();

		incorporateSignerRole();

		incorporateSignatureProductionPlace();

		incorporateCommitmentTypeIndications();

		incorporatePolicy();
	}

	private void incorporatePolicy() {

		final BLevelParameters.Policy signaturePolicy = params.bLevel().getSignaturePolicy();
		if (signaturePolicy != null && signaturePolicy.getId() != null) {

			final Element signaturePolicyIdentifierDom = DSSXMLUtils
				  .addElement(documentDom, signedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SignaturePolicyIdentifier");
			final Element signaturePolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdentifierDom, XAdESNamespaces.XAdES, "xades:SignaturePolicyId");
			if ("".equals(signaturePolicy.getId())) { // implicit

				final Element signaturePolicyImpliedDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdESNamespaces.XAdES, "xades:SignaturePolicyImplied");
			} else { // explicit

				final Element sigPolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdESNamespaces.XAdES, "xades:SigPolicyId");

				final String signaturePolicyId = signaturePolicy.getId();
				DSSXMLUtils.addTextElement(documentDom, sigPolicyIdDom, XAdESNamespaces.XAdES, "xades:Identifier", signaturePolicyId);

				if (signaturePolicy.getDigestAlgorithm() != null && signaturePolicy.getDigestValue() != null) {

					final Element sigPolicyHashDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdESNamespaces.XAdES, "xades:SigPolicyHash");

					// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					final DigestAlgorithm digestAlgorithm = signaturePolicy.getDigestAlgorithm();
					incorporateDigestMethod(sigPolicyHashDom, digestAlgorithm);

					final byte[] hashValue = signaturePolicy.getDigestValue();
					final String bas64EncodedHashValue = DSSUtils.base64Encode(hashValue);
					DSSXMLUtils.addTextElement(documentDom, sigPolicyHashDom, XMLSignature.XMLNS, "ds:DigestValue", bas64EncodedHashValue);
				}
			}
		}
	}

	/**
	 * Creates SigningTime DOM object element.
	 */
	private void incorporateSigningTime() {

		final Date signingDate = params.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(signingDate);
		final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();

		// <SigningTime>2013-11-23T11:22:52Z</SigningTime>
		final Element signingTimeDom = documentDom.createElementNS(XAdESNamespaces.XAdES, "xades:SigningTime");
		signedSignaturePropertiesDom.appendChild(signingTimeDom);
		final Text textNode = documentDom.createTextNode(xmlSigningTime);
		signingTimeDom.appendChild(textNode);
	}

	/**
	 * Creates SigningCertificate building block DOM object:
	 * <p/>
	 * <SigningCertificate> <Cert> <CertDigest> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * </CertDigest> <IssuerSerial> <ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName> <ds:X509SerialNumber>4</ds:X509SerialNumber> </IssuerSerial> </Cert>
	 * </SigningCertificate>
	 */
	private void incorporateSigningCertificate() {

		final Element signingCertificateDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SigningCertificate");

		final List<X509Certificate> certificates = new ArrayList<X509Certificate>();

		final X509Certificate signingCertificate = params.getSigningCertificate();
		certificates.add(signingCertificate);

		incorporateCertificateRef(signingCertificateDom, certificates);
	}

	/**
	 * This method incorporates the SignedDataObjectProperties DOM element <SignedDataObjectProperties> ...<DataObjectFormat ObjectReference="#detached-ref-id">
	 * ......<MimeType>text/plain</MimeType> ...</DataObjectFormat> </SignedDataObjectProperties>
	 */
	private void incorporateSignedDataObjectProperties() {

		final String dataObjectFormatObjectReference = getDataObjectFormatObjectReference();
		final String dataObjectFormatMimeType = getDataObjectFormatMimeType();

		signedDataObjectPropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdESNamespaces.XAdES, "xades:SignedDataObjectProperties");

		final Element dataObjectFormatDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:DataObjectFormat");
		dataObjectFormatDom.setAttribute("ObjectReference", dataObjectFormatObjectReference);

		final Element mimeTypeDom = DSSXMLUtils.addElement(documentDom, dataObjectFormatDom, XAdESNamespaces.XAdES, "xades:MimeType");
		DSSXMLUtils.setTextNode(documentDom, mimeTypeDom, dataObjectFormatMimeType);

		incorporateContentTimestamps();
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

					allDataObjectsTimestampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:AllDataObjectsTimeStamp");
				}
				addTimestamp(allDataObjectsTimestampDom, contentTimestamp);

			} else if (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {

				if (individualDataObjectsTimestampDom == null) {

					individualDataObjectsTimestampDom = DSSXMLUtils
						  .addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:IndividualDataObjectsTimeStamp");
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
		if (claimedSignerRoles != null || certifiedSignerRoles != null) {

			final Element signerRoleDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SignerRole");

			if (claimedSignerRoles != null && !claimedSignerRoles.isEmpty()) {

				final Element claimedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, XAdESNamespaces.XAdES, "xades:ClaimedRoles");
				addRoles(claimedSignerRoles, claimedRolesDom, "xades:ClaimedRole");
			}

			if (certifiedSignerRoles != null && !certifiedSignerRoles.isEmpty()) {

				final Element certifiedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, XAdESNamespaces.XAdES, "xades:CertifiedRoles");
				addRoles(certifiedSignerRoles, certifiedRolesDom, "xades:CertifiedRole");
			}
		}

	}

	private void addRoles(final List<String> signerRoles, final Element rolesDom, final String roleType) {

		for (final String signerRole : signerRoles) {

			final Element roleDom = DSSXMLUtils.addElement(documentDom, rolesDom, XAdESNamespaces.XAdES, roleType);
			DSSXMLUtils.setTextNode(documentDom, roleDom, signerRole);
		}
	}

	private void incorporateSignatureProductionPlace() {

		final BLevelParameters.SignerLocation signatureProductionPlace = params.bLevel().getSignerLocation();
		if (signatureProductionPlace != null) {

			final Element signatureProductionPlaceDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SignatureProductionPlace");

			final String city = signatureProductionPlace.getCity();
			if (city != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdESNamespaces.XAdES, "xades:City", city);
			}

			final String postalCode = signatureProductionPlace.getPostalCode();
			if (postalCode != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdESNamespaces.XAdES, "xades:PostalCode", postalCode);
			}

			final String stateOrProvince = signatureProductionPlace.getStateOrProvince();
			if (stateOrProvince != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdESNamespaces.XAdES, "xades:StateOrProvince", stateOrProvince);
			}

			final String country = signatureProductionPlace.getCountry();
			if (country != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdESNamespaces.XAdES, "xades:CountryName", country);
			}
		}
	}

	/**
	 * Below follows the schema definition for this element. <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
	 * <p/>
	 * <xsd:complexType name="CommitmentTypeIndicationType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeId" type="ObjectIdentifierType"/> ......<xsd:choice>
	 * .........<xsd:element name="ObjectReference" type="xsd:anyURI" maxOccurs="unbounded"/> .........< xsd:element name="AllSignedDataObjects"/> ......</xsd:choice>
	 * ......<xsd:element name="CommitmentTypeQualifiers" type="CommitmentTypeQualifiersListType" minOccurs="0"/> ...</xsd:sequence> </xsd:complexType> <xsd:complexType
	 * name="CommitmentTypeQualifiersListType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeQualifier" type="AnyType" minOccurs="0" maxOccurs="unbounded"/>
	 * ...</xsd:sequence> </xsd:complexType>
	 */
	private void incorporateCommitmentTypeIndications() {

		final List<String> commitmentTypeIndications = params.bLevel().getCommitmentTypeIndications();
		if (commitmentTypeIndications != null) {

			final Element commitmentTypeIndicationDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:CommitmentTypeIndication");

			final Element commitmentTypeIdDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdESNamespaces.XAdES, "xades:CommitmentTypeId");

			for (final String commitmentTypeIndication : commitmentTypeIndications) {

				DSSXMLUtils.addTextElement(documentDom, commitmentTypeIdDom, XAdESNamespaces.XAdES, "xades:Identifier", commitmentTypeIndication);
			}
			//final Element objectReferenceDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XADES, "ObjectReference");
			// or
			final Element allSignedDataObjectsDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdESNamespaces.XAdES, "xades:AllSignedDataObjects");

			//final Element commitmentTypeQualifiersDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XADES, "CommitmentTypeQualifiers");
		}
	}

	/**
	 * Adds signature value to the signature and returns XML signature (InMemoryDocument)
	 *
	 * @param signatureValue - Encoded value of the signature
	 * @return
	 * @throws DSSException
	 */
	public abstract DSSDocument signDocument(final byte[] signatureValue) throws DSSException;

	/**
	 * This method returns data format reference.
	 *
	 * @return
	 */
	protected abstract String getDataObjectFormatObjectReference();

	/**
	 * This method returns data format mime type.
	 *
	 * @return
	 */
	protected abstract String getDataObjectFormatMimeType();

	/**
	 * Adds the content of a timestamp into a given timestamp element
	 *
	 * @param timestampElement
	 */
	protected void addTimestamp(Element timestampElement,
	                            TimestampToken token) { //List<TimestampInclude> includes, String canonicalizationMethod, TimestampToken encapsulatedTimestamp) {
		//add includes: URI + referencedData = "true"
		//add canonicalizationMethod: Algorithm
		//add encapsulatedTimestamp: Encoding, Id, while its textContent is the base64 encoding of the data to digest
		List<TimestampInclude> includes = token.getTimestampIncludes();
		if (includes != null) {
			for (TimestampInclude include : includes) {
				Element timestampIncludeElement = documentDom.createElement("xades:Include");
				timestampIncludeElement.setAttribute("URI", "#" + include.getURI());
				timestampIncludeElement.setAttribute("referencedData", "true");
				timestampElement.appendChild((Node) timestampIncludeElement);
			}
		}
		Element canonicalizationMethodElement = documentDom.createElement("ds:CanonicalizationMethod");
		canonicalizationMethodElement.setAttribute("Algorithm", token.getCanonicalizationMethod());

		timestampElement.appendChild((Node) canonicalizationMethodElement);

		Element encapsulatedTimestampElement = documentDom.createElement("xades:EncapsulatedTimeStamp");
		encapsulatedTimestampElement.setTextContent(DSSUtils.base64Encode(token.getEncoded()));

		timestampElement.appendChild((Node) encapsulatedTimestampElement);
	}

	/**
	 * Creates XAdES TimeStamp object representation. The time stamp token is obtained from TSP source
	 *
	 * @param timestampC14nMethod
	 * @param digestValue
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	protected void createXAdESTimeStampType(final TimestampType timestampType, final String timestampC14nMethod, final byte[] digestValue) throws DSSException {

		try {

			final DigestAlgorithm timestampDigestAlgorithm = params.getTimestampDigestAlgorithm();
			if (LOG.isInfoEnabled()) {

				final String encodedDigestValue = DSSUtils.base64Encode(digestValue);
				LOG.info("Timestamp generation: " + timestampDigestAlgorithm.getName() + " / " + timestampC14nMethod + " / " + encodedDigestValue);
			}
			final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digestValue);
			final byte[] timeStampTokenBytes = timeStampToken.getEncoded();

			final String signatureTimestampId = "time-stamp-token-" + UUID.randomUUID().toString();
			final String base64EncodedTimeStampToken = DSSUtils.base64Encode(timeStampTokenBytes);

			Element timeStampDom = null;
			switch (timestampType) {

				case SIGNATURE_TIMESTAMP:
					// <xades:SignatureTimeStamp Id="time-stamp-1dee38c4-8388-40d1-8880-9eeda853fe60">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SignatureTimeStamp");
					break;
				case VALIDATION_DATA_REFSONLY_TIMESTAMP:
					break;
				case VALIDATION_DATA_TIMESTAMP:
					// <xades:SigAndRefsTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SigAndRefsTimeStamp");
					break;
				case ARCHIVE_TIMESTAMP:
					// <xades141:ArchiveTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES141, "xades141:ArchiveTimeStamp");
					break;
				case CONTENT_TIMESTAMP:
					break;
				case ALL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:AllDataObjectsTimeStamp");
					break;
				case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdESNamespaces.XAdES, "xades:IndividualDataObjectsTimeStamp");
					break;
			}
			timeStampDom.setAttribute("Id", signatureTimestampId);

			// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
			incorporateC14nMethod(timeStampDom, timestampC14nMethod);

			// <xades:EncapsulatedTimeStamp Id="time-stamp-token-6a150419-caab-4615-9a0b-6e239596643a">MIAGCSqGSIb3DQEH
			final Element encapsulatedTimeStampDom = DSSXMLUtils.addElement(documentDom, timeStampDom, XAdESNamespaces.XAdES, "xades:EncapsulatedTimeStamp");
			encapsulatedTimeStampDom.setAttribute("Id", signatureTimestampId);
			DSSXMLUtils.setTextNode(documentDom, encapsulatedTimeStampDom, base64EncodedTimeStampToken);
		} catch (IOException e) {

			throw new DSSException("Error during the creation of the XAdES timestamp!", e);
		}
	}

	private void incorporateC14nMethod(final Element parentDom, final String signedInfoC14nMethod) {

		//<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = documentDom.createElementNS(XMLSignature.XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodDom.setAttribute("Algorithm", signedInfoC14nMethod);
		parentDom.appendChild(canonicalizationMethodDom);
	}
}