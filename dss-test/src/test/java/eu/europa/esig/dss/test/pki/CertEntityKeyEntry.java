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
package eu.europa.esig.dss.test.pki;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.token.DSSPrivateKeyAccessEntry;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Implementation of {@code DSSPrivateKeyEntry} for a PKI {@code eu.europa.esig.dss.pki.model.CertEntity}
 *
 */
public class CertEntityKeyEntry implements DSSPrivateKeyAccessEntry {

    /** PKI Cert Entity entry */
    private final CertEntity certEntity;

    /**
     * Default constructor
     *
     * @param certEntity {@link CertEntity}
     */
    public CertEntityKeyEntry(final CertEntity certEntity) {
        Objects.requireNonNull(certEntity, "CertEntity cannot be null!");
        this.certEntity = certEntity;
    }

    @Override
    public CertificateToken getCertificate() {
        return certEntity.getCertificateToken();
    }

    @Override
    public CertificateToken[] getCertificateChain() {
        return certEntity.getCertificateChain().toArray(new CertificateToken[0]);
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return certEntity.getEncryptionAlgorithm();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return certEntity.getPrivateKey();
    }

}
