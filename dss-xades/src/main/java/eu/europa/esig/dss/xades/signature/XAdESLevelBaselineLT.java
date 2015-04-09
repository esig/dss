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

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;

/**
 * LT profile of XAdES signature
 *
 */
public class XAdESLevelBaselineLT extends XAdESLevelBaselineT {

	/**
	 * The default constructor for XAdESLevelBaselineLT.
	 */
	public XAdESLevelBaselineLT(final CertificateVerifier certificateVerifier) {
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

		assertExtendSignaturePossible();
		super.extendSignatureTag();

		if (xadesSignature.hasLTAProfile()) {
			return;
		}

		/**
		 * In all cases the -LT level need to be regenerated.
		 */
		checkSignatureIntegrity();

		final ValidationContext valContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

		removeOldCertificateValues();
		removeOldRevocationValues();

		final List<CertificateToken> toIncludeCertificates = getToIncludeCertificateTokens(valContext);
		incorporateCertificateValues(unsignedSignaturePropertiesDom, toIncludeCertificates);
		incorporateRevocationValues(unsignedSignaturePropertiesDom, valContext);

		/**
		 * Certificate(s), revocation data where added, XAdES signature certificate source must be reset.
		 */
		xadesSignature.resetCertificateSource();
		xadesSignature.resetRevocationSources();
	}

	/**
	 * This method checks the signature integrity and throws a {@code DSSException} if the signature is broken.
	 *
	 * @throws eu.europa.esig.dss.DSSException
	 */
	protected void checkSignatureIntegrity() throws DSSException {

		final SignatureCryptographicVerification signatureCryptographicVerification = xadesSignature.checkSignatureIntegrity();
		if (!signatureCryptographicVerification.isSignatureIntact()) {

			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
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
	 * This method removes old certificates values from the unsigned signature properties element.
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

			incorporateCrlTokens(revocationValuesDom, revocationsForInclusion.crlTokens);
			incorporateOcspTokens(revocationValuesDom, revocationsForInclusion.ocspTokens);
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

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignaturePossible() throws DSSException {

		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel) && xadesSignature.hasLTAProfile()) {

			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "XAdES LTA"));
		}
	}
}
