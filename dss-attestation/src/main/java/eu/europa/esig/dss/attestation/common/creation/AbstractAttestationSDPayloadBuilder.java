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
package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.attestation.common.key.DefaultPublicKeyInfoFactory;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfoFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.random.DSSSecureRandomProvider;
import eu.europa.esig.dss.spi.random.SecureRandomProvider;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Abstract implementation of an attestation payload builder.
 *
 * @param <P> implementation of {@link AttestationPayloadParameters} for the attestation format
 * @param <D> implementation of {@link SelectiveDisclosure} for the attestation format
 */
public abstract class AbstractAttestationSDPayloadBuilder<P extends AttestationPayloadParameters, D extends SelectiveDisclosure> implements AttestationSDPayloadBuilder<P, D> {

    /**
     * Provides a SecureRandom for salt computation
     */
    private SecureRandomProvider secureRandomProvider = new DSSSecureRandomProvider(DigestAlgorithm.SHA256);

    /**
     * The factory is used to build a representation of a public key from a {@code java.security.PublicKey}
     * Default : {@code DefaultPublicKeyInfoFactory}
     */
    private PublicKeyInfoFactory publicKeyInfoFactory = new DefaultPublicKeyInfoFactory();

    /**
     * Default constructor
     */
    protected AbstractAttestationSDPayloadBuilder() {
        // empty
    }

    /**
     * Sets a SecureRandomProvider used for a deterministic SecureRandom production
     *
     * @param secureRandomProvider {@link SecureRandomProvider}
     */
    public void setSecureRandomProvider(SecureRandomProvider secureRandomProvider) {
        Objects.requireNonNull(secureRandomProvider, "SecureRandomProvider cannot be null!");
        this.secureRandomProvider = secureRandomProvider;
    }

    /**
     * Gets the PublicKeyInfoFactory
     *
     * @return {@link PublicKeyInfoFactory}
     */
    protected PublicKeyInfoFactory getPublicKeyInfoFactory() {
        return publicKeyInfoFactory;
    }

    /**
     * (Optional) allows modifying the default behavior for a COSE_Key computation from a {@code java.security.PublicKey}.
     * Default : an instance of {@code PublicKeyInfoFactory} is used, relying on JDK 8 and BouncyCastle utility methods.
     *
     * @param publicKeyInfoFactory {@link PublicKeyInfoFactory}
     */
    public void setPublicKeyInfoFactory(PublicKeyInfoFactory publicKeyInfoFactory) {
        Objects.requireNonNull(publicKeyInfoFactory, "PublicKeyInfoFactory cannot be null!");
        this.publicKeyInfoFactory = publicKeyInfoFactory;
    }

    /**
     * Creates a new SecureRandom using the {@code payloadParameters} for the initial seed computation.
     * NOTE: this method is intended to provide a deterministic behavior.
     *
     * @param payloadParameters {@link AttestationPayloadParameters}
     * @return {@link SecureRandom}
     */
    protected SecureRandom secureRandom(AttestationPayloadParameters payloadParameters) {
        return secureRandomProvider.getSecureRandom(payloadParameters.toString().getBytes());
    }

    /**
     * This method generates the next random salt using the {@code secureRandom}
     * By default, the method generates a 128-bit length salt.
     *
     * @param secureRandom {@link SecureRandom}
     * @return byte array containing the salt
     */
    protected byte[] nextRandomSalt(SecureRandom secureRandom) {
        return secureRandom.generateSeed(16); // 16 * 8 = 128 bits
    }

}
