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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Set;

/**
 * XL profile of XAdES signature
 *
 */
public class XAdESLevelXL extends XAdESLevelX {

	/**
	 * The default constructor for XAdESLevelXL.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
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
		Element levelXUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

		if (!xadesSignature.hasLTProfile() || SignatureLevel.XAdES_XL.equals(params.getSignatureLevel())) {

			// Data sources can already be loaded in memory (force reload)
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
			xadesSignature.resetTimestampSource();

			final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

			String afterCertificateText = removeOldCertificateValues();
			removeOldRevocationValues();

			final ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(validationContext);

			Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
			List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
			List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();
			
			incorporateCertificateValues(unsignedSignaturePropertiesDom, certificateValuesToAdd, afterCertificateText);
			incorporateRevocationValues(unsignedSignaturePropertiesDom, crlsToAdd, ocspsToAdd, afterCertificateText);
			
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelXUnsignedProperties);
		}
	}

	/**
	 * This method removes old certificate values from the unsigned signature properties element.
	 */
	private String removeOldCertificateValues() {
		String text = null;
		final Element toRemove = xadesSignature.getCertificateValues();
		if (toRemove != null) {
			text = removeChild(unsignedSignaturePropertiesDom, toRemove);
			xadesSignature.resetCertificateSource();
		}
		return text;
	}

	/**
	 * This method removes old revocation values from the unsigned signature properties element.
	 */
	private void removeOldRevocationValues() {
		final Element toRemove = xadesSignature.getRevocationValues();
		if (toRemove != null) {
			removeChild(unsignedSignaturePropertiesDom, toRemove);
			xadesSignature.resetRevocationSources();
		}
	}

}
