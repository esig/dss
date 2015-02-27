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

import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;

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
	 * Adds <CertificateValues> and <RevocationValues> segments to <UnsignedSignatureProperties>.<br>
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

		if (!xadesSignature.hasXLProfile() || SignatureLevel.XAdES_XL.equals(params.getSignatureLevel())) {

			final ValidationContext valContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

			removeOldCertificateValues();
			removeOldRevocationValues();

			final List<CertificateToken> toIncludeCertificateTokens = getToIncludeCertificateTokens(valContext);
			incorporateCertificateValues(unsignedSignaturePropertiesDom, toIncludeCertificateTokens);
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
	 * @param parentDom
	 * @param validationContext
	 */
	protected void incorporateRevocationValues(final Element parentDom, final ValidationContext validationContext) {

		// <xades:RevocationValues>

		final DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusion = xadesSignature.getRevocationDataForInclusion(validationContext);

		if (!revocationsForInclusion.isEmpty()) {

			final Element revocationValuesDom = DSSXMLUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:RevocationValues");

			incorporateOcspTokens(revocationValuesDom, revocationsForInclusion.ocspTokens);
			incorporateCrlTokens(revocationValuesDom, revocationsForInclusion.crlTokens);
		}
	}

	private void incorporateCrlTokens(final Element parentDom, final List<CRLToken> crlTokens) {

		if (crlTokens.isEmpty()) {

			return;
		}
		// ...<xades:CRLValues/>
		final Element crlValuesDom = DSSXMLUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:CRLValues");

		for (final RevocationToken revocationToken : crlTokens) {

			final byte[] encodedCRL = revocationToken.getEncoded();
			final String base64EncodedCRL = Base64.encodeBase64String(encodedCRL);
			DSSXMLUtils.addTextElement(documentDom, crlValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedCRLValue", base64EncodedCRL);
		}
	}

	private void incorporateOcspTokens(Element parentDom, final List<OCSPToken> ocspTokens) {

		if (ocspTokens.isEmpty()) {

			return;
		}

		// ...<xades:OCSPValues>
		// .........<xades:EncapsulatedOCSPValue>MIIERw...
		final Element ocspValuesDom = DSSXMLUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:OCSPValues");

		for (final RevocationToken revocationToken : ocspTokens) {

			final byte[] encodedOCSP = revocationToken.getEncoded();
			final String base64EncodedOCSP = Base64.encodeBase64String(encodedOCSP);
			DSSXMLUtils.addTextElement(documentDom, ocspValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedOCSPValue", base64EncodedOCSP);
		}
	}
}
