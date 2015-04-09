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

import java.math.BigInteger;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public abstract class XAdESBuilder {

	protected static final Logger LOG = LoggerFactory.getLogger(XAdESBuilder.class);

	public static final String DS_CANONICALIZATION_METHOD = "ds:CanonicalizationMethod";
	public static final String DS_DIGEST_METHOD = "ds:DigestMethod";
	public static final String DS_DIGEST_VALUE = "ds:DigestValue";
	public static final String DS_KEY_INFO = "ds:KeyInfo";
	public static final String DS_OBJECT = "ds:Object";
	public static final String DS_REFERENCE = "ds:Reference";
	public static final String DS_SIGNATURE = "ds:Signature";
	public static final String DS_SIGNATURE_METHOD = "ds:SignatureMethod";
	public static final String DS_SIGNATURE_VALUE = "ds:SignatureValue";
	public static final String DS_SIGNED_INFO = "ds:SignedInfo";
	public static final String DS_TRANSFORM = "ds:Transform";
	public static final String DS_TRANSFORMS = "ds:Transforms";
	public static final String DS_X509_CERTIFICATE = "ds:X509Certificate";
	public static final String DS_X509_DATA = "ds:X509Data";
	public static final String DS_X509_ISSUER_NAME = "ds:X509IssuerName";
	public static final String DS_X509_SERIAL_NUMBER = "ds:X509SerialNumber";
	public static final String DS_XPATH = "ds:XPath";

	public static final String XADES_ALL_DATA_OBJECTS_TIME_STAMP = "xades:AllDataObjectsTimeStamp";
	public static final String XADES_ALL_SIGNED_DATA_OBJECTS = "xades:AllSignedDataObjects";
	public static final String XADES_COUNTER_SIGNATURE = "xades:CounterSignature";
	public static final String XADES_CERT = "xades:Cert";
	public static final String XADES_CERT_DIGEST = "xades:CertDigest";
	public static final String XADES_CERTIFICATE_VALUES = "xades:CertificateValues";
	public static final String XADES_CERTIFIED_ROLES = "xades:CertifiedRoles";
	public static final String XADES_CERTIFIED_ROLE = "xades:CertifiedRole";
	public static final String XADES_CITY = "xades:City";
	public static final String XADES_CLAIMED_ROLES = "xades:ClaimedRoles";
	public static final String XADES_CLAIMED_ROLE = "xades:ClaimedRole";
	public static final String XADES_COMMITMENT_TYPE_ID = "xades:CommitmentTypeId";
	public static final String XADES_COMMITMENT_TYPE_INDICATION = "xades:CommitmentTypeIndication";
	public static final String XADES_COUNTRY_NAME = "xades:CountryName";
	public static final String XADES_DATA_OBJECT_FORMAT = "xades:DataObjectFormat";
	public static final String XADES_ENCAPSULATED_TIME_STAMP = "xades:EncapsulatedTimeStamp";
	public static final String XADES_ENCAPSULATED_X509_CERTIFICATE = "xades:EncapsulatedX509Certificate";
	public static final String XADES_IDENTIFIER = "xades:Identifier";
	public static final String XADES_DESCRIPTION = "xades:Description";
	public static final String XADES_INCLUDE = "xades:Include";
	public static final String XADES_INDIVIDUAL_DATA_OBJECTS_TIME_STAMP = "xades:IndividualDataObjectsTimeStamp";
	public static final String XADES_ISSUER_SERIAL = "xades:IssuerSerial";
	public static final String XADES_MIME_TYPE = "xades:MimeType";
	public static final String XADES_POSTAL_CODE = "xades:PostalCode";
	public static final String XADES_QUALIFYING_PROPERTIES = "xades:QualifyingProperties";
	public static final String XADES_SIG_AND_REFS_TIME_STAMP = "xades:SigAndRefsTimeStamp";
	public static final String XADES_SIG_POLICY_HASH = "xades:SigPolicyHash";
	public static final String XADES_SIG_POLICY_ID = "xades:SigPolicyId";
	public static final String XADES_SIGNATURE_POLICY_ID = "xades:SignaturePolicyId";
	public static final String XADES_SIGNATURE_POLICY_IDENTIFIER = "xades:SignaturePolicyIdentifier";
	public static final String XADES_SIGNATURE_POLICY_IMPLIED = "xades:SignaturePolicyImplied";
	public static final String XADES_SIGNATURE_POLICY_QUALIFIERS = "xades:SigPolicyQualifiers";
	public static final String XADES_SIGNATURE_POLICY_QUALIFIER = "xades:SigPolicyQualifier";
	public static final String XADES_SPURI = "xades:SPURI";
	public static final String XADES_SIGNATURE_PRODUCTION_PLACE = "xades:SignatureProductionPlace";
	public static final String XADES_SIGNATURE_TIME_STAMP = "xades:SignatureTimeStamp";
	public static final String XADES_SIGNED_DATA_OBJECT_PROPERTIES = "xades:SignedDataObjectProperties";
	public static final String XADES_SIGNED_PROPERTIES = "xades:SignedProperties";
	public static final String XADES_SIGNED_SIGNATURE_PROPERTIES = "xades:SignedSignatureProperties";
	public static final String XADES_UNSIGNED_PROPERTIES = "xades:UnsignedProperties";
	public static final String XADES_UNSIGNED_SIGNATURE_PROPERTIES = "xades:UnsignedSignatureProperties";
	public static final String XADES_SIGNER_ROLE = "xades:SignerRole";
	public static final String XADES_SIGNING_TIME = "xades:SigningTime";
	public static final String XADES_STATE_OR_PROVINCE = "xades:StateOrProvince";

	public static final String XADES141_ARCHIVE_TIME_STAMP = "xades141:ArchiveTimeStamp";

	public static final String ALGORITHM = "Algorithm";
	public static final String ID = "Id";
	public static final String OBJECT_REFERENCE = "ObjectReference";
	public static final String REFERENCED_DATA = "referencedData";
	public static final String SIGNATURE = "Signature";
	public static final String TARGET = "Target";
	public static final String TYPE = "Type";
	public static final String URI = "URI";

	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";

	public static final String HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT = "http://www.w3.org/2000/09/xmldsig#Object";
	/**
	 * This XPath filter allows to remove all ds:Signature elements from the XML
	 */
	public static final String NOT_ANCESTOR_OR_SELF_DS_SIGNATURE = "not(ancestor-or-self::ds:Signature)";

	/**
	 * This variable holds the {@code XPathQueryHolder} which contains all constants and queries needed to cope with the default signature schema.
	 */
	protected final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();

	/*
	 * This variable is a reference to the set of parameters relating to the structure and process of the creation or
	 * extension of the electronic signature.
	 */
	protected XAdESSignatureParameters params;

	/**
	 * This is the variable which represents the root XML document root (with signature).
	 */
	protected Document documentDom;

	/**
	 * Reference to the object in charge of certificates validation
	 */
	protected CertificateVerifier certificateVerifier;

	/**
	 * The default constructor.
	 *
	 * @param certificateVerifier {@code CertificateVerifier}
	 */
	public XAdESBuilder(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * This method allows to retrieve the {@code CertificatePool} containing trust anchors.
	 *
	 * @return {@code CertificatePool} or null
	 */
	protected CertificatePool getCertificatePool() {

		final CertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();
		if (trustedCertSource != null) {
			return trustedCertSource.getCertificatePool();
		}
		return null;
	}

	/**
	 * This method creates the ds:DigestMethod DOM object
	 *
	 * @param parentDom
	 * @param digestAlgorithm digest algorithm xml identifier
	 */
	protected void incorporateDigestMethod(final Element parentDom, final DigestAlgorithm digestAlgorithm) {

		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final Element digestMethodDom = documentDom.createElementNS(XMLNS, DS_DIGEST_METHOD);
		final String digestAlgorithmXmlId = digestAlgorithm.getXmlId();
		digestMethodDom.setAttribute(ALGORITHM, digestAlgorithmXmlId);
		parentDom.appendChild(digestMethodDom);
	}

	/**
	 * This method creates the ds:DigestValue DOM object.
	 *
	 * @param parentDom
	 * @param digestAlgorithm  digest algorithm
	 * @param originalDocument to digest array of bytes
	 */
	protected void incorporateDigestValue(final Element parentDom, final DigestAlgorithm digestAlgorithm, final DSSDocument originalDocument) {

		// <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
		final Element digestValueDom = documentDom.createElementNS(XMLNS, DS_DIGEST_VALUE);
		final String base64EncodedDigestBytes = originalDocument.getDigest(digestAlgorithm);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Digest value {} --> {}", parentDom.getNodeName(), base64EncodedDigestBytes);
		}
		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);
		parentDom.appendChild(digestValueDom);
	}

	/**
	 * Incorporates the certificate's references as a child of the given parent node. The first element of the {@code X509Certificate} {@code List} MUST be the signing
	 * certificate.
	 *
	 * @param signingCertificateDom DOM parent element
	 * @param certificates          {@code List} of the certificates to be incorporated
	 */
	protected void incorporateCertificateRef(final Element signingCertificateDom, final List<CertificateToken> certificates) {

		for (final CertificateToken certificate : certificates) {

			final Element certDom = DSSXMLUtils.addElement(documentDom, signingCertificateDom, XAdES, XADES_CERT);

			final Element certDigestDom = DSSXMLUtils.addElement(documentDom, certDom, XAdES, XADES_CERT_DIGEST);

			final DigestAlgorithm signingCertificateDigestMethod = params.bLevel().getSigningCertificateDigestMethod();
			incorporateDigestMethod(certDigestDom, signingCertificateDigestMethod);

			final InMemoryDocument inMemoryCertificate = new InMemoryDocument(certificate.getEncoded());
			incorporateDigestValue(certDigestDom, signingCertificateDigestMethod, inMemoryCertificate);

			final Element issuerSerialDom = DSSXMLUtils.addElement(documentDom, certDom, XAdES, XADES_ISSUER_SERIAL);

			final Element x509IssuerNameDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, XMLNS, DS_X509_ISSUER_NAME);
			final String issuerX500PrincipalName = certificate.getIssuerX500Principal().getName();
			DSSXMLUtils.setTextNode(documentDom, x509IssuerNameDom, issuerX500PrincipalName);

			final Element x509SerialNumberDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, XMLNS, DS_X509_SERIAL_NUMBER);
			final BigInteger serialNumber = certificate.getSerialNumber();
			final String serialNumberString = new String(serialNumber.toString());
			DSSXMLUtils.setTextNode(documentDom, x509SerialNumberDom, serialNumberString);
		}
	}
}