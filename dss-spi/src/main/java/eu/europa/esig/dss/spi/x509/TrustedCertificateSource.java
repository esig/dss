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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;

/**
 * The interface provides an abstraction of a {@code eu.europa.esig.dss.spi.x509.CertificateSource}
 * containing trust anchors
 *
 */
public interface TrustedCertificateSource extends CertificateSource {

    /**
     * Returns a list of alternative OCSP access point Urls for certificates issued by the current trust anchor
     *
     * @param trustAnchor {@link CertificateToken}
     * @return a list of {@link String}s
     */
    List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor);

    /**
     * Returns a list of alternative CRL access point Urls for certificates issued by the current trust anchor
     *
     * @param trustAnchor {@link CertificateToken}
     * @return a list of {@link String}s
     */
    List<String> getAlternativeCRLUrls(CertificateToken trustAnchor);

}
