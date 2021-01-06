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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.w3c.dom.Element;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Contains XAdES-C profile aspects
 *
 */
public class XAdESLevelC extends XAdESLevelBaselineT {

	/**
	 * The default constructor for XAdESLevelC.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelC(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * This method incorporates CRL References like
	 * 
	 * <pre>
	 * {@code
	 *	 <xades:CRLRefs>
	 *	 	<xades:CRLRef>
	 *			<xades:DigestAlgAndValue>
	 *				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
	 *				<ds:DigestValue>G+z+DaZ6X44wEOueVYvZGmTh4dBkjjctKxcJYEV4HmU=</ds:DigestValue>
	 *			</xades:DigestAlgAndValue>
	 *			<xades:CRLIdentifier URI="LevelACAOK.crl">
	 *				<xades:Issuer>CN=LevelACAOK,OU=Plugtests_STF-428_2011-2012,O=ETSI,C=FR</xades:Issuer>
	 *				<xades:IssueTime>2012-03-13T13:58:28.000-03:00</xades:IssueTime>
	 *			<xades:Number>4415260066222</xades:Number>
	 * }
	 * </pre>
	 * 
	 * @param completeRevocationRefsDom
	 * @param processedRevocationTokens
	 * @throws DSSException
	 */
	private void incorporateCRLRefs(Element completeRevocationRefsDom, final Set<RevocationToken<Revocation>> processedRevocationTokens) throws DSSException {

		if (processedRevocationTokens.isEmpty()) {

			return;
		}

		boolean containsCrlToken = false;
		for (RevocationToken revocationToken : processedRevocationTokens) {
			containsCrlToken = revocationToken instanceof CRLToken;
			if (containsCrlToken) {
				break;
			}
		}

		if (!containsCrlToken) {
			return;
		}

		final Element crlRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRefs());

		for (final RevocationToken revocationToken : processedRevocationTokens) {

			if (revocationToken instanceof CRLToken) {

				final CRLToken crl = ((CRLToken) revocationToken);

				final Element crlRefDom = DomUtils.addElement(documentDom, crlRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRef());

				final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(), getCurrentXAdESElements().getElementDigestAlgAndValue());
				// TODO: to be added as field to eu.europa.esig.dss.AbstractSignatureParameters.
				DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
				DSSXMLUtils.incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm, getXmldsigNamespace());

				incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, revocationToken);

				final Element crlIdentifierDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLIdentifier());
				// crlIdentifierDom.setAttribute("URI",".crl");
				final String issuerX500PrincipalName = crl.getIssuerX500Principal().getName();
				DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssuer(), issuerX500PrincipalName);

				final Date thisUpdate = crl.getThisUpdate();
				XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(thisUpdate);
				final String thisUpdateAsXmlFormat = xmlGregorianCalendar.toXMLFormat();
				DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(),getCurrentXAdESElements().getElementIssueTime(), thisUpdateAsXmlFormat);

				// DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Number", ???);
			}
		}
	}

	/**
	 * This method adds OCSP References like :
	 * 
	 * <pre>
	 * {@code
	 * 	<xades:CRLRefs/>
	 *	<xades:OCSPRefs>
	 *		<xades:OCSPRef>
	 *			<xades:OCSPIdentifier>
	 *				<xades:ResponderID>
	 *					<xades:ByName>C=AA,O=DSS,CN=OCSP A</xades:ByName>
	 *				</xades:ResponderID>
	 *				<xades:ProducedAt>2013-11-25T12:33:34.000+01:00</xades:ProducedAt>
	 *			</xades:OCSPIdentifier>
	 *			<xades:DigestAlgAndValue>
	 *				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 *				<ds:DigestValue>O1uHdchN+zFzbGrBg2FP3/idD0k=</ds:DigestValue>
	 *				...
	 *}
	 * </pre>
	 * 
	 * @param completeRevocationRefsDom
	 * @param processedRevocationTokens
	 * @throws eu.europa.esig.dss.model.DSSException
	 */
	private void incorporateOCSPRefs(final Element completeRevocationRefsDom, final Set<RevocationToken<Revocation>> processedRevocationTokens)
			throws DSSException {

		if (processedRevocationTokens.isEmpty()) {

			return;
		}

		boolean containsOCSPToken = false;
		for (RevocationToken revocationToken : processedRevocationTokens) {
			containsOCSPToken = revocationToken instanceof OCSPToken;
			if (containsOCSPToken) {
				break;
			}
		}

		if (!containsOCSPToken) {
			return;
		}

		final Element ocspRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementOCSPRefs());

		for (RevocationToken revocationToken : processedRevocationTokens) {

			if (revocationToken instanceof OCSPToken) {

				BasicOCSPResp basicOcspResp = ((OCSPToken) revocationToken).getBasicOCSPResp();
				if (basicOcspResp != null) {

					final Element ocspRefDom = DomUtils.addElement(documentDom, ocspRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementOCSPRef());

					final Element ocspIdentifierDom = DomUtils.addElement(documentDom, ocspRefDom, 
							getXadesNamespace(), getCurrentXAdESElements().getElementOCSPIdentifier());
					final Element responderIDDom = DomUtils.addElement(documentDom, ocspIdentifierDom, 
							getXadesNamespace(), getCurrentXAdESElements().getElementResponderID());

					final RespID respID = basicOcspResp.getResponderId();
					final ResponderId responderId = DSSRevocationUtils.getDSSResponderId(respID);
					
					if (responderId.getX500Principal() != null) {
						DomUtils.addTextElement(documentDom, responderIDDom, getXadesNamespace(), 
								getCurrentXAdESElements().getElementByName(), responderId.getX500Principal().toString());
					} else {
						final String base64EncodedKeyHashOctetStringBytes = Utils.toBase64(responderId.getSki());
						DomUtils.addTextElement(documentDom, responderIDDom, getXadesNamespace(), 
								getCurrentXAdESElements().getElementByKey(), base64EncodedKeyHashOctetStringBytes);
					}

					final Date producedAt = basicOcspResp.getProducedAt();
					final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(producedAt);
					final String producedAtXmlEncoded = xmlGregorianCalendar.toXMLFormat();
					DomUtils.addTextElement(documentDom, ocspIdentifierDom, getXadesNamespace(), 
							getCurrentXAdESElements().getElementProducedAt(), producedAtXmlEncoded);

					final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, ocspRefDom, 
							getXadesNamespace(), getCurrentXAdESElements().getElementDigestAlgAndValue());
					// TODO: to be added as field to eu.europa.esig.dss.AbstractSignatureParameters.
					DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
					DSSXMLUtils.incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm, getXmldsigNamespace());

					incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, revocationToken);
				}
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
	 * Adds {@code <CompleteCertificateRefs>} and {@code <CompleteRevocationRefs>} segments into
	 * {@code <UnsignedSignatureProperties>} element.
	 *
	 * There SHALL be at most <b>one occurrence of CompleteRevocationRefs and CompleteCertificateRefs</b> properties in
	 * the signature. Old references must be removed.
	 *
	 * @see XAdESLevelBaselineT#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		super.extendSignatureTag();
		Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

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
			removeChild(unsignedSignaturePropertiesDom, toRemove);

			final Element completeCertificateRefsDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, 
					getXadesNamespace(), getCurrentXAdESElements().getElementCompleteCertificateRefs());

			final Element certRefsDom = DomUtils.addElement(documentDom, completeCertificateRefsDom, 
					getXadesNamespace(), getCurrentXAdESElements().getElementCertRefs());

			final CertificateToken certificateToken = xadesSignature.getSigningCertificateToken();
			final Set<CertificateToken> processedCertificateTokens = validationContext.getProcessedCertificates();
			final Set<CertificateToken> processedCertificateTokenList = new HashSet<>();
			processedCertificateTokenList.addAll(processedCertificateTokens);
			processedCertificateTokenList.remove(certificateToken);
			final Set<CertificateToken> x509CertificateProcessedList = processedCertificateTokenList;
			incorporateCertificateRef(certRefsDom, x509CertificateProcessedList);

			toRemove = xadesSignature.getCompleteRevocationRefs();
			removeChild(unsignedSignaturePropertiesDom, toRemove);

			// <xades:CompleteRevocationRefs>
			final Element completeRevocationRefsDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, 
					getXadesNamespace(), getCurrentXAdESElements().getElementCompleteRevocationRefs());
			incorporateCRLRefs(completeRevocationRefsDom, validationContext.getProcessedRevocations());
			incorporateOCSPRefs(completeRevocationRefsDom, validationContext.getProcessedRevocations());
			
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
		}
	}

}
