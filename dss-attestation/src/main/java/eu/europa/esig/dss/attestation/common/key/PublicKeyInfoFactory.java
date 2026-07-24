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
package eu.europa.esig.dss.attestation.common.key;

import java.security.PublicKey;

/**
 * Factory for creating a provider-independent {@link PublicKeyInfo}
 * representation from a {@link PublicKey}.
 * <p>
 * Implementations are responsible for extracting the relevant public key
 * parameters from provider-specific key implementations and converting them
 * into a generic {@link PublicKeyInfo} model.
 * <p>
 * The resulting {@link PublicKeyInfo} can subsequently be transformed into
 * different representations, such as COSE_Key or JWK.
 */
public interface PublicKeyInfoFactory {

    /**
     * Creates a provider-independent representation of the given public key.
     *
     * @param publicKey {@link PublicKey} to convert
     * @return {@link PublicKeyInfo}
     */
    PublicKeyInfo create(PublicKey publicKey);

}
