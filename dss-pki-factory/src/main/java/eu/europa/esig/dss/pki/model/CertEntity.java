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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.List;

/**
 * An interface representing a certificate entity with essential properties.
 * <p>
 * This interface defines methods to access key information, certificate chain, the certificate token,
 * and the encryption algorithm associated with the certificate entity.
 *
 * @see CertificateToken
 * @see EncryptionAlgorithm
 */
public interface CertEntity extends Serializable {

    /**
     * Gets the private key associated with this certificate entity.
     *
     * @return private key as a {@link PrivateKey} object
     */
    PrivateKey getPrivateKey();

    /**
     * Gets the certificate chain associated with this certificate entity.
     *
     * @return a list of {@link CertificateToken} objects representing the certificate chain.
     */
    List<CertificateToken> getCertificateChain();

    /**
     * Gets the certificate token associated with this certificate entity.
     *
     * @return the certificate token as a {@link CertificateToken} object.
     */
    CertificateToken getCertificateToken();

    /**
     * Gets the encryption algorithm associated with this certificate entity.
     *
     * @return the encryption algorithm as an {@link EncryptionAlgorithm} object.
     */
    EncryptionAlgorithm getEncryptionAlgorithm();

}
