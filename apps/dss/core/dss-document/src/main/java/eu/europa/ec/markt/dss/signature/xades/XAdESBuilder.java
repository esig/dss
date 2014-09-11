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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

public abstract class XAdESBuilder {

	public static final String DS_CANONICALIZATION_METHOD = "ds:CanonicalizationMethod";
	public static final String DS_COUNTER_SIGNATURE = "ds:CounterSignature";
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
	public static final String DS_UNSIGNED_PROPERTIES = "ds:UnsignedProperties";
	public static final String DS_UNSIGNED_SIGNATURE_PROPERTIES = "ds:UnsignedSignatureProperties";
	public static final String DS_X509_CERTIFICATE = "ds:X509Certificate";
	public static final String DS_X509_DATA = "ds:X509Data";
	public static final String DS_X509_ISSUER_NAME = "ds:X509IssuerName";
	public static final String DS_X509_SERIAL_NUMBER = "ds:X509SerialNumber";
	public static final String DS_XPATH = "ds:XPath";

	public static final String XADES_ALL_DATA_OBJECTS_TIME_STAMP = "xades:AllDataObjectsTimeStamp";
	public static final String XADES_ALL_SIGNED_DATA_OBJECTS = "xades:AllSignedDataObjects";
	public static final String XADES_CERT = "xades:Cert";
	public static final String XADES_CERT_DIGEST = "xades:CertDigest";
	public static final String XADES_CERTIFIED_ROLES = "xades:CertifiedRoles";
	public static final String XADES_CITY = "xades:City";
	public static final String XADES_CLAIMED_ROLES = "xades:ClaimedRoles";
	public static final String XADES_COMMITMENT_TYPE_ID = "xades:CommitmentTypeId";
	public static final String XADES_COMMITMENT_TYPE_INDICATION = "xades:CommitmentTypeIndication";
	public static final String XADES_COUNTRY_NAME = "xades:CountryName";
	public static final String XADES_DATA_OBJECT_FORMAT = "xades:DataObjectFormat";
	public static final String XADES_ENCAPSULATED_TIME_STAMP = "xades:EncapsulatedTimeStamp";
	public static final String XADES_IDENTIFIER = "xades:Identifier";
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
	public static final String XADES_SIGNATURE_PRODUCTION_PLACE = "xades:SignatureProductionPlace";
	public static final String XADES_SIGNATURE_TIME_STAMP = "xades:SignatureTimeStamp";
	public static final String XADES_SIGNED_DATA_OBJECT_PROPERTIES = "xades:SignedDataObjectProperties";
	public static final String XADES_SIGNED_PROPERTIES = "xades:SignedProperties";
	public static final String XADES_SIGNED_SIGNATURE_PROPERTIES = "xades:SignedSignatureProperties";
	public static final String XADES_SIGNER_ROLE = "xades:SignerRole";
	public static final String XADES_SIGNING_CERTIFICATE = "xades:SigningCertificate";
	public static final String XADES_SIGNING_TIME = "xades:SigningTime";
	public static final String XADES_STATE_OR_PROVINCE = "xades:StateOrProvince";

	public static final String XADES141_ARCHIVE_TIME_STAMP = "xades141:ArchiveTimeStamp";

	public static final String ALGORITHM = "Algorithm";
	public static final String ID = "Id";
	public static final String TARGET = "Target";
	public static final String TYPE = "Type";
	public static final String URI = "URI";

	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";

	public static final String HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT = "http://www.w3.org/2000/09/xmldsig#Object";
	public static final String HTTP_WWW_W3_ORG_TR_1999_REC_XPATH_19991116 = "http://www.w3.org/TR/1999/REC-xpath-19991116";

	/**
	 * This variable holds the {@code XPathQueryHolder} which contains all constants and queries needed to cope with the default signature schema.
	 */
	protected final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();

	protected static final Logger LOG = LoggerFactory.getLogger(XAdESBuilder.class);

	/*
	 * This variable is a reference to the set of parameters relating to the structure and process of the creation or
	 * extension of the electronic signature.
	 */
	protected SignatureParameters params;

	/**
	 * This is the variable which represents the root XML document root (with signature).
	 */
	protected Document documentDom;

	/**
	 * This method creates the ds:DigestMethod DOM object
	 *
	 * @param parentDom
	 * @param digestAlgorithm digest algorithm xml identifier
	 */
	protected void incorporateDigestMethod(final Element parentDom, final DigestAlgorithm digestAlgorithm) {

		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final Element digestMethodDom = documentDom.createElementNS(XMLSignature.XMLNS, DS_DIGEST_METHOD);
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
		final Element digestValueDom = documentDom.createElementNS(XMLSignature.XMLNS, DS_DIGEST_VALUE);
		final String base64EncodedDigestBytes = originalDocument.getDigest(digestAlgorithm);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Digest value {} --> {}", parentDom.getNodeName(), base64EncodedDigestBytes);
		}
		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);
		parentDom.appendChild(digestValueDom);
	}

	/**
	 * Incorporates the certificate's reference as a child of the given parent node.
	 *
	 * @param signingCertificateDom
	 * @param certificates
	 */
	protected void incorporateCertificateRef(final Element signingCertificateDom, final List<X509Certificate> certificates) {

		final Element certDom = DSSXMLUtils.addElement(documentDom, signingCertificateDom, XAdESNamespaces.XAdES, XADES_CERT);

		final Element certDigestDom = DSSXMLUtils.addElement(documentDom, certDom, XAdESNamespaces.XAdES, XADES_CERT_DIGEST);

		final DigestAlgorithm signingCertificateDigestMethod = params.bLevel().getSigningCertificateDigestMethod();
		incorporateDigestMethod(certDigestDom, signingCertificateDigestMethod);

		for (final X509Certificate certificate : certificates) {

			final InMemoryDocument inMemoryCertificate = new InMemoryDocument(DSSUtils.getEncoded(certificate));
			incorporateDigestValue(certDigestDom, signingCertificateDigestMethod, inMemoryCertificate);

			final Element issuerSerialDom = DSSXMLUtils.addElement(documentDom, certDom, XAdESNamespaces.XAdES, XADES_ISSUER_SERIAL);

			final Element x509IssuerNameDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, XMLSignature.XMLNS, DS_X509_ISSUER_NAME);
			final String issuerX500PrincipalName = DSSUtils.getIssuerX500PrincipalName(certificate);
			DSSXMLUtils.setTextNode(documentDom, x509IssuerNameDom, issuerX500PrincipalName);

			final Element x509SerialNumberDom = DSSXMLUtils.addElement(documentDom, issuerSerialDom, XMLSignature.XMLNS, DS_X509_SERIAL_NUMBER);
			final BigInteger serialNumber = certificate.getSerialNumber();
			final String serialNumberString = new String(serialNumber.toString());
			DSSXMLUtils.setTextNode(documentDom, x509SerialNumberDom, serialNumberString);
		}
	}
}