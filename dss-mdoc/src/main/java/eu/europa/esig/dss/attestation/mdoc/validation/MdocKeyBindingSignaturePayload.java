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
package eu.europa.esig.dss.attestation.mdoc.validation;

import java.util.Map;

import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.spi.attestation.KeyBindingSignaturePayload;

/**
 * Implementation of {@link KeyBindingSignaturePayload} for ISO/IEC 18013-5 mdoc
 */
public class MdocKeyBindingSignaturePayload extends MdocVerifiedClaimMap implements KeyBindingSignaturePayload {

    /**
     * Default constructor
     *
     * @param payload {@link Map}
     */
    public MdocKeyBindingSignaturePayload(final Map<?, ?> payload) {
        super(payload);
    }

    @Override
    public VerifiedClaimString getNonce() {
        // Not present in mdoc
        return null;
    }

    @Override
    public VerifiedClaimDate getIssuedAt() {
        // Not present in mdoc
        return null;
    }

    @Override
    public VerifiedClaimString getAudience() {
        // Not present in mdoc
        return null;
    }

    @Override
    public VerifiedClaimString getSdHash() {
        // Not present in mdoc
        return null;
    }
}
