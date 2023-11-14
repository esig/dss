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
package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Map;

/**
 * This interface represents a repository for CertEntity objects.
 * It provides methods for querying and managing stored certificate entities.
 *
 * @param <T> {@code CertEntity} representing a repository entry.
 */
public interface CertEntityRepository<T extends CertEntity> {

    /**
     * Retrieves the certificate entity associated with the given certificate token.
     *
     * @param certificateToken The certificate token to search for.
     * @return The certificate entity associated with the provided token, or null if not found.
     */
    T getByCertificateToken(CertificateToken certificateToken);

    /**
     * Retrieves the revocation list associated with the parent certificate entity.
     *
     * @param parent The parent certificate entity.
     * @return A list containing the revocation entities associated with the parent certificate.
     */
    Map<T, CertEntityRevocation> getRevocationList(T parent);

    /**
     * Retrieves the revocation information for the given certificate entity.
     *
     * @param certEntity The certificate entity .
     * @return The revocation information  .
     */
    CertEntityRevocation getRevocation(T certEntity);

    /**
     * Retrieves the issuer certificate entity for the given certificate entity.
     *
     * @param certEntity The certificate entity.
     * @return The issuer certificate entity .
     */
    CertEntity getIssuer(T certEntity);

}
