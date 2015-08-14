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

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;

/**
 * Contains XAdES-C profile aspects
 *
 *
 */

public class XAdESLevelC extends XAdESLevelBaselineT {

	/**
	 * The default constructor for XAdESLevelC.
	 *
	 * @throws javax.xml.datatype.DatatypeConfigurationException
	 */
	public XAdESLevelC(CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
	}

	private void incorporateCRLRefs(Element completeRevocationRefsDom, final Set<RevocationToken> processedRevocationTokens) throws DSSException {

		if (processedRevocationTokens.isEmpty()) {

			return;
		}
		// <xades:CRLRefs>
		// ...<xades:CRLRef>
		// ......<xades:DigestAlgAndValue>
		// .........<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		// .........<ds:DigestValue>G+z+DaZ6X44wEOueVYvZGmTh4dBkjjctKxcJYEV4HmU=</ds:DigestValue>
		// ......</xades:DigestAlgAndValue>
		// ......<xades:CRLIdentifier URI="LevelACAOK.crl">
		// ...<xades:Issuer>CN=LevelACAOK,OU=Plugtests_STF-428_2011-2012,O=ETSI,C=FR</xades:Issuer>
		// ...<xades:IssueTime>2012-03-13T13:58:28.000-03:00</xades:IssueTime>
		// ...<xades:Number>4415260066222</xades:Number>

		final Element crlRefsDom = DSSXMLUtils.addElement(documentDom, completeRevocationRefsDom, XAdESNamespaces.XAdES, "xades:CRLRefs");

		for (final RevocationToken revocationToken : processedRevocationTokens) {

			if (revocationToken instanceof CRLToken) {

				final X509CRL crl = ((CRLToken) revocationToken).getX509crl();

				final Element crlRefDom = DSSXMLUtils.addElement(documentDom, crlRefsDom, XAdESNamespaces.XAdES, "xades:CRLRef");

				final Element digestAlgAndValueDom = DSSXMLUtils.addElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:DigestAlgAndValue");
				// TODO: to be added as field to eu.europa.esig.dss.AbstractSignatureParameters.
				DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
				incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);

				final InMemoryDocument inMemoryDocument = new InMemoryDocument(revocationToken.getEncoded());
				incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, inMemoryDocument);

				// final Element crlIdentifierDom = DSSXMLUtils.addElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:CRLIdentifier");
				// crlIdentifierDom.setAttribute("URI",".crl");
				final String issuerX500PrincipalName = crl.getIssuerX500Principal().getName();
				DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Issuer", issuerX500PrincipalName);

				final Date thisUpdate = crl.getThisUpdate();
				XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(thisUpdate);
				final String thisUpdateAsXmlFormat = xmlGregorianCalendar.toXMLFormat();
				DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:IssueTime", thisUpdateAsXmlFormat);

				// DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Number", ???);
			}
		}
	}

	/**
	 * @param completeRevocationRefsDom
	 * @param processedRevocationTokens
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private void incorporateOCSPRefs(final Element completeRevocationRefsDom, final Set<RevocationToken> processedRevocationTokens) throws DSSException {

		if (processedRevocationTokens.isEmpty()) {

			return;
		}
		// ...<xades:CRLRefs/>
		// ...<xades:OCSPRefs>
		// ......<xades:OCSPRef>
		// .........<xades:OCSPIdentifier>
		// ............<xades:ResponderID>
		// ...............<xades:ByName>C=AA,O=DSS,CN=OCSP A</xades:ByName>
		// ............</xades:ResponderID>
		// ............<xades:ProducedAt>2013-11-25T12:33:34.000+01:00</xades:ProducedAt>
		// .........</xades:OCSPIdentifier>
		// .........<xades:DigestAlgAndValue>
		// ............<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
		// ............<ds:DigestValue>O1uHdchN+zFzbGrBg2FP3/idD0k=</ds:DigestValue>

		final Element ocspRefsDom = DSSXMLUtils.addElement(documentDom, completeRevocationRefsDom, XAdESNamespaces.XAdES, "xades:OCSPRefs");

		for (RevocationToken revocationToken : processedRevocationTokens) {

			if (revocationToken instanceof OCSPToken) {

				BasicOCSPResp basicOcspResp = ((OCSPToken) revocationToken).getBasicOCSPResp();

				final Element ocspRefDom = DSSXMLUtils.addElement(documentDom, ocspRefsDom, XAdESNamespaces.XAdES, "xades:OCSPRef");

				final Element ocspIdentifierDom = DSSXMLUtils.addElement(documentDom, ocspRefDom, XAdESNamespaces.XAdES, "xades:OCSPIdentifier");
				final Element responderIDDom = DSSXMLUtils.addElement(documentDom, ocspIdentifierDom, XAdESNamespaces.XAdES, "xades:ResponderID");

				final RespID responderId = basicOcspResp.getResponderId();
				final ResponderID responderIdAsASN1Object = responderId.toASN1Object();
				final DERTaggedObject derTaggedObject = (DERTaggedObject) responderIdAsASN1Object.toASN1Primitive();
				if (2 == derTaggedObject.getTagNo()) {

					final ASN1OctetString keyHashOctetString = (ASN1OctetString) derTaggedObject.getObject();
					final byte[] keyHashOctetStringBytes = keyHashOctetString.getOctets();
					final String base65EncodedKeyHashOctetStringBytes = Base64.encodeBase64String(keyHashOctetStringBytes);
					DSSXMLUtils.addTextElement(documentDom, responderIDDom, XAdESNamespaces.XAdES, "xades:ByKey", base65EncodedKeyHashOctetStringBytes);
				} else {

					final ASN1Primitive derObject = derTaggedObject.getObject();
					final X500Name name = X500Name.getInstance(derObject);
					DSSXMLUtils.addTextElement(documentDom, responderIDDom, XAdESNamespaces.XAdES, "xades:ByName", name.toString());
				}

				final Date producedAt = basicOcspResp.getProducedAt();
				final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(producedAt);
				final String producedAtXmlEncoded = xmlGregorianCalendar.toXMLFormat();
				DSSXMLUtils.addTextElement(documentDom, ocspIdentifierDom, XAdESNamespaces.XAdES, "xades:ProducedAt", producedAtXmlEncoded);

				final Element digestAlgAndValueDom = DSSXMLUtils.addElement(documentDom, ocspRefDom, XAdESNamespaces.XAdES, "xades:DigestAlgAndValue");
				// TODO: to be added as field to eu.europa.esig.dss.AbstractSignatureParameters.
				DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
				incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);

				final InMemoryDocument inMemoryDocument = new InMemoryDocument(revocationToken.getEncoded());
				incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, inMemoryDocument);
			}
		}
	}

	/**
	 * This format builds up taking XAdES-T signature and incorporating additional data required for validation:
	 *
	 * The sequence of references to the full set of CA certificates that have been used to validate the electronic
	 * signature up to (but not including ) the signer's certificate.<br>
	 * A full set of references to the revocation data that have been used in the validation of the signer and CA
	 * certificates.<br>
	 * Adds <CompleteCertificateRefs> and <CompleteRevocationRefs> segments into <UnsignedSignatureProperties> element.
	 *
	 * There SHALL be at most <b>one occurrence of CompleteRevocationRefs & CompleteCertificateRefs</b> properties in the
	 * signature. Old references must be removed.
	 *
	 * @see XAdESLevelBaselineT#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		super.extendSignatureTag();

		final SignatureLevel signatureLevel = params.getSignatureLevel();
		// for XAdES_XL the development is not conform with the standard
		if (!xadesSignature.hasCProfile() || SignatureLevel.XAdES_C.equals(signatureLevel) || SignatureLevel.XAdES_XL.equals(signatureLevel)) {

			final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

			// XAdES-C: complete certificate references
			// <xades:CompleteCertificateRefs>
			// ...<xades:CertRefs>
			// ......<xades:Cert>
			// .........<xades:CertDigest>

			// XAdES-C: complete revocation references
			Element toRemove = xadesSignature.getCompleteCertificateRefs();
			if (toRemove != null) {
				unsignedSignaturePropertiesDom.removeChild(toRemove);
			}

			final Element completeCertificateRefsDom = DSSXMLUtils
					.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:CompleteCertificateRefs");

			final Element certRefsDom = DSSXMLUtils.addElement(documentDom, completeCertificateRefsDom, XAdESNamespaces.XAdES, "xades:CertRefs");

			final CertificateToken certificateToken = xadesSignature.getSigningCertificateToken();
			final Set<CertificateToken> processedCertificateTokens = validationContext.getProcessedCertificates();
			final List<CertificateToken> processedCertificateTokenList = new ArrayList<CertificateToken>();
			processedCertificateTokenList.addAll(processedCertificateTokens);
			processedCertificateTokenList.remove(certificateToken);
			final List<CertificateToken> x509CertificateProcessedList = processedCertificateTokenList;
			incorporateCertificateRef(certRefsDom, x509CertificateProcessedList);


			toRemove = xadesSignature.getCompleteRevocationRefs();
			if (toRemove != null) {
				unsignedSignaturePropertiesDom.removeChild(toRemove);
			}

			// <xades:CompleteRevocationRefs>
			final Element completeRevocationRefsDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:CompleteRevocationRefs");
			incorporateCRLRefs(completeRevocationRefsDom, validationContext.getProcessedRevocations());
			incorporateOCSPRefs(completeRevocationRefsDom, validationContext.getProcessedRevocations());
		}
	}
}
