/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;
import java.util.Map;

/**
 * This interface provides an abstraction for a certificate source containing information about
 * a validation status of Trusted Lists and corresponding trust properties
 *
 */
public interface TrustPropertiesCertificateSource extends TrustedCertificateSourceWithTime {

    /**
     * Gets TL Validation job summary
     *
     * @return {@link TLValidationJobSummary}
     */
    TLValidationJobSummary getSummary();

    /**
     * Sets TL Validation job summary
     *
     * @param summary {@link TLValidationJobSummary}
     */
    void setSummary(TLValidationJobSummary summary);

    /**
     * Returns TrustProperties for the given certificate, when applicable
     *
     * @param token {@link CertificateToken}
     * @return a list of {@link TrustProperties}
     */
    List<TrustProperties> getTrustServices(CertificateToken token);

    /**
     * The method allows to fill the CertificateSource
     *
     * @param trustPropertiesByCerts map between {@link CertificateToken}s and a list of {@link TrustProperties}
     */
    void setTrustPropertiesByCertificates(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts);

    /**
     * The method allows to fill the CertificateSource with trusted time periods
     *
     * @param trustTimeByCertificate map between {@link CertificateToken}s and a list of {@link CertificateTrustTime}s
     */
    void setTrustTimeByCertificates(final Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCertificate);

}
