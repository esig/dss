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

import java.util.List;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

/**
 * XL profile of XAdES signature
 *
 */
public class XAdESLevelXL extends XAdESLevelX {

	/**
	 * The default constructor for XAdESLevelXL.
	 */
	public XAdESLevelXL(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds CertificateValues and RevocationValues segments to UnsignedSignatureProperties.<br>
	 * 
	 * An XML electronic signature MAY contain at most one:<br>
	 * - CertificateValues element and<br>
	 * - RevocationValues element.
	 *
	 * @see XAdESLevelX#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		/* Go up to -X */
		super.extendSignatureTag();

		if (!xadesSignature.hasLTProfile() || SignatureLevel.XAdES_XL.equals(params.getSignatureLevel())) {

			// Timestamps can already be loaded in memory (force reload)
			xadesSignature.resetTimestamps();

			final ValidationContext valContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

			removeOldCertificateValues();
			removeOldRevocationValues();

			incorporateCertificateValues(unsignedSignaturePropertiesDom, valContext);
			incorporateRevocationValues(unsignedSignaturePropertiesDom, valContext);

			/**
			 * Certificate(s), revocation data where added, XAdES signature certificate source must be reset.
			 */
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
		}
	}

	/**
	 * This method removes old revocation values from the unsigned signature properties element.
	 */
	private void removeOldRevocationValues() {

		final Element toRemove = xadesSignature.getRevocationValues();
		if (toRemove != null) {

			unsignedSignaturePropertiesDom.removeChild(toRemove);
			xadesSignature.resetRevocationSources();
		}
	}

	/**
	 * This method removes old certificate values from the unsigned signature properties element.
	 */
	private void removeOldCertificateValues() {

		final Element toRemove = xadesSignature.getCertificateValues();
		if (toRemove != null) {

			unsignedSignaturePropertiesDom.removeChild(toRemove);
			xadesSignature.resetCertificateSource();
		}
	}

	/**
	 * This method incorporates revocation values.
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:RevocationValues>
	 * 	}
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param validationContext
	 *            the validation context with the revocation data
	 */
	protected void incorporateRevocationValues(final Element parentDom, final ValidationContext validationContext) {
		final DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusion = xadesSignature.getRevocationDataForInclusion(validationContext);

		if (!revocationsForInclusion.isEmpty()) {
			final Element revocationValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:RevocationValues");
			incorporateCrlTokens(revocationValuesDom, revocationsForInclusion.crlTokens);
			incorporateOcspTokens(revocationValuesDom, revocationsForInclusion.ocspTokens);
		}
	}

	/**
	 * This method incorporates the CRLValues :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:CRLValues>
	 * 			<xades:EncapsulatedCRLValue>...</xades:EncapsulatedCRLValue>
	 * 			...
	 * 		</xades:CRLValues>
	 * 	}
	 * </pre>
	 * 
	 * @param parentDom
	 *            the parent element
	 * @param crlTokens
	 *            the list of CRL Tokens to be added
	 */
	private void incorporateCrlTokens(final Element parentDom, final List<CRLToken> crlTokens) {
		if (crlTokens.isEmpty()) {
			return;
		}
		final Element crlValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:CRLValues");

		for (final RevocationToken revocationToken : crlTokens) {
			final byte[] encodedCRL = revocationToken.getEncoded();
			final String base64EncodedCRL = Utils.toBase64(encodedCRL);
			DomUtils.addTextElement(documentDom, crlValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedCRLValue", base64EncodedCRL);
		}
	}

	/**
	 * This method incorporates the OCSP responses :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:OCSPValues>
	 * 			<xades:EncapsulatedOCSPValue>...</xades:EncapsulatedOCSPValue>
	 * 			...
	 * 		</xades:OCSPValues>
	 * 	}
	 * </pre>
	 * 
	 * @param parentDom
	 *            the parent element
	 * @param ocspTokens
	 *            the list of OCSP Tokens to be added
	 */
	private void incorporateOcspTokens(Element parentDom, final List<OCSPToken> ocspTokens) {
		if (ocspTokens.isEmpty()) {
			return;
		}

		final Element ocspValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:OCSPValues");

		for (final RevocationToken revocationToken : ocspTokens) {
			final byte[] encodedOCSP = revocationToken.getEncoded();
			final String base64EncodedOCSP = Utils.toBase64(encodedOCSP);
			DomUtils.addTextElement(documentDom, ocspValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedOCSPValue", base64EncodedOCSP);
		}
	}

}
