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
package eu.europa.esig.dss.signature;

import java.util.LinkedList;
import java.util.List;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.CertificateReorderer;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * This class is used to retrieve the used certificates for a signature from the user parameters.
 * 
 * It avoids duplicate entries, orders certificates from the signing certificate to the Root CA and filters trust
 * anchors depending of the policy
 */
public class BaselineBCertificateSelector extends CertificateReorderer {

	private final CertificateVerifier certificateVerifier;
	private final AbstractSignatureParameters parameters;

	public BaselineBCertificateSelector(CertificateVerifier certificateVerifier, AbstractSignatureParameters parameters) {
		super(parameters.getSigningCertificate(), parameters.getCertificateChain());
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
	}

	public List<CertificateToken> getCertificates() {

		List<CertificateToken> orderedCertificates = getOrderedCertificates();
		
		ListCertificateSource trustedCertSources = certificateVerifier.getTrustedCertSources();

		// if true, trust anchor certificates (and upper certificates) are not included in the signature
		if (parameters.bLevel().isTrustAnchorBPPolicy() && !trustedCertSources.isEmpty()) {

			List<CertificateToken> result = new LinkedList<>();
			for (CertificateToken certificateToken : orderedCertificates) {
				if (trustedCertSources.isTrusted(certificateToken)) {
					break;
				}
				result.add(certificateToken);
			}

			return result;
		} else {
			return orderedCertificates;
		}
	}

}
