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
package eu.europa.esig.dss.attestation.sd.jwt.claim;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTUtils;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;

import java.util.List;

/**
 * SD-JWT implementation of a {@code ClaimArray}
 *
 */
public class SDJWTVerifiedClaimArray extends VerifiedClaimArray {

    private static final long serialVersionUID = 8097598759991618602L;

    /**
     * Constructor with claim name and selectively disclosable revocation and a parent claim provided
     *
     * @param name {@link String} claim header name
     * @param value a list of {@link VerifiedClaim}s representing the original array value
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link VerifiedClaim} representing the parent claim, when applicable
     */
    public SDJWTVerifiedClaimArray(final String name, final List<?> value, final boolean selectivelyDisclosable, final VerifiedClaim parent) {
        super(name, value, selectivelyDisclosable, parent);
    }

    @Override
    protected VerifiedClaim createClaim(Object value) {
        return SDJWTUtils.createClaim(null, this, value);
    }

}
