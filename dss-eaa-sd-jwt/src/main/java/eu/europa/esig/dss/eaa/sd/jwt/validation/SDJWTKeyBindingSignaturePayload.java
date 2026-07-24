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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import java.util.Map;

import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimMap;
import eu.europa.esig.dss.model.eaa.claim.ClaimDate;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.spi.eaa.KeyBindingSignaturePayload;

/**
 * Implementation of {@link KeyBindingSignaturePayload} for SD-JWT EAA
 */
public class SDJWTKeyBindingSignaturePayload extends SDJWTClaimMap implements KeyBindingSignaturePayload {

    SDJWTKeyBindingSignaturePayload(final Map<String, Object> payload) {
        super(payload);
    }

    @Override
    public ClaimString getNonce() {
        return getAsString(SDJWTConstants.NONCE);
    }

    @Override
    public ClaimDate getIssuedAt() {
        return getAsDateTime(SDJWTConstants.ISSUED_AT);
    }

    @Override
    public ClaimString getAudience() {
        return getAsString(SDJWTConstants.AUDIENCE);
    }

    @Override
    public ClaimString getSdHash() {
        return getAsString(SDJWTConstants.SD_HASH);
    }

}
