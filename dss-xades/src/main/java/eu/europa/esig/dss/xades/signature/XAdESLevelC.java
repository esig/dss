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
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.w3c.dom.Element;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

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
	 * @see XAdESLevelBaselineT#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		boolean cLevelRequired = false;

		// Reset sources
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			// for XL-level it is required to re-initialize refs
			if (!cLevelExtensionRequired(params.getSignatureLevel())) {
				continue;
			}

			// Data sources can already be loaded in memory (force reload)
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
			xadesSignature.resetTimestampSource();

			cLevelRequired = true;
		}

		if (!cLevelRequired) {
			return;
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentValidator.getValidationData(signatures);

		// Append ValidationData
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (!cLevelExtensionRequired(params.getSignatureLevel())) {
				continue;
			}

			assertExtendSignatureToCPossible();

			String indent = removeOldCertificateRefs();
			removeOldRevocationRefs();

			ValidationData validationDataForInclusion = getValidationDataForCLevelInclusion(validationDataContainer, signature);

			Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			// XAdES-C: complete certificate references
			// <xades:CompleteCertificateRefs>
			// ...<xades:CertRefs>
			// ......<xades:Cert>
			// .........<xades:CertDigest>
			incorporateCertificateRefs(unsignedSignaturePropertiesDom, validationDataForInclusion.getCertificateTokens(), indent);

			// XAdES-C: complete revocation references
			// <xades:CompleteRevocationRefs>
			if (Utils.isCollectionNotEmpty(validationDataForInclusion.getCrlTokens()) ||
					Utils.isCollectionNotEmpty(validationDataForInclusion.getOcspTokens())) {
				final Element completeRevocationRefsDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom,
						getXadesNamespace(), getCurrentXAdESElements().getElementCompleteRevocationRefs());
				incorporateCRLRefs(completeRevocationRefsDom, validationDataForInclusion.getCrlTokens());
				incorporateOCSPRefs(completeRevocationRefsDom, validationDataForInclusion.getOcspTokens());
			}

			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
		}

	}

	private boolean cLevelExtensionRequired(SignatureLevel signatureLevel) {
		return !xadesSignature.hasCProfile() || SignatureLevel.XAdES_C.equals(signatureLevel) ||
				SignatureLevel.XAdES_XL.equals(signatureLevel);
	}

	private String removeOldCertificateRefs() {
		String text = null;
		final Element toRemove = xadesSignature.getCompleteCertificateRefs();
		if (toRemove != null) {
			text = removeNode(toRemove);
			/* Because the element was removed, the certificate source needs to be reset */
			xadesSignature.resetCertificateSource();
		}
		return text;
	}

	private void removeOldRevocationRefs() {
		final Element toRemove = xadesSignature.getCompleteRevocationRefs();
		if (toRemove != null) {
			removeNode(toRemove);
			/* Because the element was removed, the revocation sources need to be reset */
			xadesSignature.resetRevocationSources();
		}
	}

	private void incorporateCertificateRefs(Element parentDom, Collection<CertificateToken> certificatesToBeAdded,
											String indent) {
		if (Utils.isCollectionNotEmpty(certificatesToBeAdded)) {
			final Element completeCertificateRefsDom = createCompleteCertificateRefsDom(parentDom);
			final Element certRefsDom = createCertRefsDom(completeCertificateRefsDom);

			DigestAlgorithm tokenReferencesDigestAlgorithm = params.getTokenReferencesDigestAlgorithm();
			for (final CertificateToken certificateToken : certificatesToBeAdded) {
				incorporateCert(certRefsDom, certificateToken, tokenReferencesDigestAlgorithm);
			}
		}

	}

	private Element createCompleteCertificateRefsDom(Element parentDom) {
		if (params.isEn319132()) {
			return DomUtils.addElement(documentDom, parentDom, getXades141Namespace(),
					XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2);
		} else {
			return DomUtils.addElement(documentDom, parentDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementCompleteCertificateRefs());
		}
	}

	private Element createCertRefsDom(Element parentDom) {
		if (params.isEn319132()) {
			return DomUtils.addElement(documentDom, parentDom, getXades141Namespace(),
					XAdES141Element.CERT_REFS);
		} else {
			return DomUtils.addElement(documentDom, parentDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementCertRefs());
		}
	}

	private ValidationData getValidationDataForCLevelInclusion(final ValidationDataContainer validationDataContainer,
															   final AdvancedSignature signature) {
		ValidationData validationData = validationDataContainer.getAllValidationDataForSignature(signature);
		validationData.excludeCertificateTokens(getCertificateTokensForExclusion());
		return validationData;
	}

	private Collection<CertificateToken> getCertificateTokensForExclusion() {
		/*
		 * A.1.1 The CompleteCertificateRefsV2 qualifying property
		 *
		 * The CompleteCertificateRefsV2 qualifying property:
		 * ...
		 * 2) Shall not contain the reference to the signing certificate.
		 * ...
		 */
		CertificateToken signingCertificateToken = xadesSignature.getSigningCertificateToken();
		if (signingCertificateToken != null) {
			return Collections.singletonList(signingCertificateToken);
		}
		return Collections.emptyList();
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
	 * @param completeRevocationRefsDom {@link Element} "CompleteRevocationRefs"
	 * @param crlTokens a collection of {@link CRLToken}s to add
	 */
	private void incorporateCRLRefs(Element completeRevocationRefsDom,
									Collection<CRLToken> crlTokens) {
		if (crlTokens.isEmpty()) {
			return;
		}

		final Element crlRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRefs());

		for (final CRLToken crlToken : crlTokens) {

			final Element crlRefDom = DomUtils.addElement(documentDom, crlRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLRef());

			DigestAlgorithm digestAlgorithm = params.getTokenReferencesDigestAlgorithm();
			final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(),
					getCurrentXAdESElements().getElementDigestAlgAndValue());
			incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);
			incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, crlToken);

			final Element crlIdentifierDom = DomUtils.addElement(documentDom, crlRefDom, getXadesNamespace(), getCurrentXAdESElements().getElementCRLIdentifier());
			// crlIdentifierDom.setAttribute("URI",".crl");
			final String issuerX500PrincipalName = crlToken.getIssuerX500Principal().getName();
			DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssuer(), issuerX500PrincipalName);

			final Date thisUpdate = crlToken.getThisUpdate();
			XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(thisUpdate);
			final String thisUpdateAsXmlFormat = xmlGregorianCalendar.toXMLFormat();
			DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(),getCurrentXAdESElements().getElementIssueTime(), thisUpdateAsXmlFormat);

			// DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Number", ???);

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
	 * @param completeRevocationRefsDom {@link Element} "CompleteRevocationRefs"
	 * @param ocspTokens a collection of {@link OCSPToken}s to add
	 */
	private void incorporateOCSPRefs(Element completeRevocationRefsDom,
									 Collection<OCSPToken> ocspTokens) {
		if (ocspTokens.isEmpty()) {
			return;
		}

		final Element ocspRefsDom = DomUtils.addElement(documentDom, completeRevocationRefsDom, getXadesNamespace(), getCurrentXAdESElements().getElementOCSPRefs());

		for (OCSPToken ocspToken : ocspTokens) {

			BasicOCSPResp basicOcspResp = ocspToken.getBasicOCSPResp();
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

				DigestAlgorithm digestAlgorithm = params.getTokenReferencesDigestAlgorithm();
				final Element digestAlgAndValueDom = DomUtils.addElement(documentDom, ocspRefDom, getXadesNamespace(),
						getCurrentXAdESElements().getElementDigestAlgAndValue());
				incorporateDigestMethod(digestAlgAndValueDom, digestAlgorithm);
				incorporateDigestValue(digestAlgAndValueDom, digestAlgorithm, ocspToken);
			}

		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToCPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_C.equals(signatureLevel) && (xadesSignature.hasXProfile() ||
				xadesSignature.hasLTProfile() || xadesSignature.hasLTAProfile())) {
			final String exceptionMessage = "Cannot extend signature. The signature is already extended with [%s].";
			throw new IllegalInputException(String.format(exceptionMessage, "XAdES X"));
		} else if (xadesSignature.areAllSelfSignedCertificates()) {
			throw new IllegalInputException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
