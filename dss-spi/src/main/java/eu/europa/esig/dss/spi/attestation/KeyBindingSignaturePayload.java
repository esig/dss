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
package eu.europa.esig.dss.spi.attestation;

import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimDate;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * Represents a key binding signature payload
 *
 */
public interface KeyBindingSignaturePayload extends Claim {

    /**
     * Gets the value of the nonce from the key binding payload
     *
     * @return {@link ClaimString}
     */
    ClaimString getNonce();

    /**
     * Gets the issuance date from the key binding payload
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getIssuedAt();

    /**
     * Gets the value of the audience from the key binding payload
     *
     * @return {@link ClaimString}
     */
    ClaimString getAudience();

    /**
     * Gets the value of the "sd_hash" from the key binding payload
     *
     * @return {@link ClaimString}
     */
    ClaimString getSdHash();
}
