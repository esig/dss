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
package eu.europa.esig.dss.attestation.mdoc.claim;

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimArray;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;

/**
 * deviceKey contains the public part of the key pair used for mdoc authentication (see 9.1.3.4). The
 * deviceKey element is encoded as an untagged COSE_Key element as specified in RFC 8152; further
 * requirements are defined in 9.1.5.2.
 *
 */
public class MdocClaimDeviceKey extends MdocClaimMap {

    private static final long serialVersionUID = 4939740857897930307L;

    /**
     * Constructor to initialize MdocClaimDevice from a ClaimMap
     *
     * @param value {@link ClaimMap}
     */
    public MdocClaimDeviceKey(ClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    /**
     * Gets the identification of the key type claim
     *
     * @return {@link Claim}
     */
    public Claim getKTY() {
        return get(COSEConstants.COSE_KEY_KTY);
    }

    /**
     * Gets the key identification value -- match to kid in message claim
     *
     * @return {@link ClaimByteString}
     */
    public ClaimByteString getKID() {
        return getAsByteString(COSEConstants.COSE_KEY_KID);
    }

    /**
     * Gets the key usage restriction to this algorithm claim
     *
     * @return {@link Claim}
     */
    public Claim getALG() {
        return get(COSEConstants.COSE_KEY_ALG);
    }

    /**
     * Gets the restrict set of permissible operations claim
     *
     * @return {@link ClaimArray}
     */
    public ClaimArray getKeyOps() {
        return getAsArray(COSEConstants.COSE_KEY_KEY_OPS);
    }

    /**
     * Gets the Base IV to be xor-ed with Partial IVs
     *
     * @return {@link ClaimByteString}
     */
    public ClaimByteString getBaseIV() {
        return getAsByteString(COSEConstants.COSE_KEY_BASE_IV);
    }

}
