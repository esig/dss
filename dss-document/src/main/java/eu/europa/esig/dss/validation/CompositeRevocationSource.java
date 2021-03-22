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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

/**
 * This interface allows retrieving of Revocation data from CRL or OCSP sources, whatever is available
 *
 * NOTE: The implemented object does not require setting of OCSP/CRL/TrustedCertificate sources
 *       on instantiation from the user.
 *       All the values are automatically configured and set in {@code eu.europa.esig.dss.validation.SignatureValidationContext}
 *       based on the parameters defined in the provided {@code eu.europa.esig.dss.validation.CertificateVerifier}
 *
 */
public interface CompositeRevocationSource extends RevocationSource<Revocation> {

	/**
	 * Sets the CRLSource
	 *
	 * @param crlSource {@link RevocationSource}
	 */
	void setCrlSource(RevocationSource<CRL> crlSource);

	/**
	 * Sets the OCSPSource
	 *
	 * @param ocspSource {@link RevocationSource}
	 */
	void setOcspSource(RevocationSource<OCSP> ocspSource);

	/**
	 * Sets a trusted certificate source in order to accept trusted OCSPToken's certificate issuers
	 * 
	 * @param trustedListCertificateSource {@link ListCertificateSource}
	 */
	void setTrustedCertificateSource(ListCertificateSource trustedListCertificateSource);

}
