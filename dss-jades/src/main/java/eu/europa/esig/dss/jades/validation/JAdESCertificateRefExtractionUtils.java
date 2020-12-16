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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.jwx.HeaderParameterNames;

import java.util.Map;

/**
 * Contains utils for a certificate reference extraction
 */
public final class JAdESCertificateRefExtractionUtils {

	private JAdESCertificateRefExtractionUtils() {
	}

	/**
	 * Parses the xRefs component value and returns {@code CertificateRef}
	 *
	 * @param certificateRefMap a map representing the xRefs component value
	 * @return {@link CertificateRef} of the value has been parsed successfully, FALSE otherwise
	 */
	public static CertificateRef createCertificateRef(Map<?, ?> certificateRefMap) {
		IssuerSerial issuerSerial = DSSJsonUtils.getIssuerSerial((String) certificateRefMap.get(HeaderParameterNames.KEY_ID));

		Digest digest = DSSJsonUtils.getDigest(certificateRefMap);
		if (digest != null) {
			CertificateRef certificateRef = new CertificateRef();
			certificateRef.setCertDigest(digest);
			if (issuerSerial != null) {
				certificateRef.setCertificateIdentifier(DSSASN1Utils.toCertificateIdentifier(issuerSerial));
			}
			return certificateRef;
		}

		return null;
	}

}
