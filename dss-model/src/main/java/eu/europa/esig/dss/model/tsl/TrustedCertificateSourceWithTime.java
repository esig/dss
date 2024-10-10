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
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This trusted certificate source defines a collection of trusted certificates with a given trusted validity range,
 * during which a certificate is considered as a trust anchor
 *
 */
public interface TrustedCertificateSourceWithTime {

    /**
     * Returns trust time period for the given certificate, when the certificate is considered as a trust anchor.
     * For an unbounded period of trust time, returns a {@code CertificateTrustTime} with empty values.
     * When the certificate is not trusted at any time, returns not trusted {@code CertificateTrustTime} entry.
     *
     * @param token {@link CertificateToken}
     * @return {@link CertificateTrustTime}
     */
    CertificateTrustTime getTrustTime(CertificateToken token);

}
