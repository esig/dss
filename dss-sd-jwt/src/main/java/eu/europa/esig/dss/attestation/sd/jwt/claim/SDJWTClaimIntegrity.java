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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.attestation.claim.ClaimIntegrity;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SD-JWT implementation of a claim integrity.
 * The claim integrity is used for those claims, suffixed with "#integrity" string.
 *
 */
public class SDJWTClaimIntegrity extends ClaimString implements ClaimIntegrity {

    private static final long serialVersionUID = -1585182324348523330L;

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTClaimIntegrity.class);

    /**
     * Default constructor
     *
     * @param value {@link ClaimString}
     */
    public SDJWTClaimIntegrity(ClaimString value) {
        super(value.getName(), value.getStringValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public DigestAlgorithm getDigestAlgorithm() {
        String[] parts = getStringValue().split("-");
        if (parts.length > 1) {
            String srIntegrityId = parts[0];
            try {
                return DigestAlgorithm.forSrIntegrityId(srIntegrityId);
            } catch (IllegalArgumentException e) {
                LOG.warn("Unable to find a corresponding DigestAlgorithm for integrity claim for value '{}'!", srIntegrityId);
            }
        }
        return null;
    }

    @Override
    public byte[] getDigestValue() {
        String[] parts = getStringValue().split("-");
        if (parts.length > 1) {
            /*
             * Digest are expected to be Base64 encoded.
             * See {@code https://www.w3.org/TR/2016/REC-SRI-20160623/#integrity-metadata}
             */
            String digestValueB64 = parts[1];
            if (Utils.isBase64Encoded(digestValueB64)) {
                return Utils.fromBase64(digestValueB64);
            } else {
                LOG.warn("The #integrity bytes are not base64 encoded!");
            }
        }
        return null;
    }

    @Override
    public boolean isSubresourceIntegrityType() {
        return true;
    }

}
