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
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Set;

/**
 * Interface that allows loading of issuing certificates
 * by defined AIA URI within a {@code eu.europa.esig.dss.model.x509.CertificateToken}
 *
 */
public interface AIASource {

    /**
     * Loads a set of {@code CertificateToken}s accessed by AIA URIs from the provided {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get issuer candidates for
     * @return a set of issuer candidates accessed by AIA URIs
     */
    Set<CertificateToken> getCertificatesByAIA(final CertificateToken certificateToken);

}
