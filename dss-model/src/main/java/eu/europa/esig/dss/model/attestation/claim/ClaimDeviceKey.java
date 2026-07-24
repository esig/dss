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
package eu.europa.esig.dss.model.attestation.claim;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

/**
 * Represents a device key used for creating a key-binding signature.
 *
 */
public interface ClaimDeviceKey extends Claim {

    /**
     * Gets the public key
     *
     * @return {@link PublicKey}
     */
    PublicKey getPublicKey();

    /**
     * Gets a list of provided certificates
     *
     * @return a list of {@link CertificateToken}s
     */
    List<CertificateToken> getCertificates();

    /**
     * Gets a list of certificate digests
     *
     * @return a list of {@link Digest}s
     */
    List<Digest> getCertificateDigests();

    /**
     * Gets a list of certificate key identifiers (KID)
     *
     * @return a list of {@link String}s
     */
    List<String> getCertificateKeyIdentifiers();

    /**
     * Gets a list of certificate access URLs
     *
     * @return a list of {@link String}s
     */
    List<String> getCertificateUrls();

    /**
     * Gets a list of namespaces the key is authorized to sign
     *
     * @return a list of {@link String}s
     */
    List<String> getAuthorizedNamespaces();

    /**
     * Gets a map of namespaces and applicable data element lists the key is authorized to sign
     *
     * @return a map of {@link String} namespaces and lists of {@link String} data elements
     */
    Map<String, List<String>> getAuthorizedDataElements();

}
