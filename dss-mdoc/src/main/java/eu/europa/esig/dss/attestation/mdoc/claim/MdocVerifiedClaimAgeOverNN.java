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

import eu.europa.esig.dss.attestation.mdoc.ISO180135Headers;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeOverNN;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBoolean;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mdoc representation of an "age_over_NN" claim as defined in "7.2 mDL data" of ISO/IEC 18013-5.
 * 
 */
public class MdocVerifiedClaimAgeOverNN extends VerifiedClaimBoolean implements VerifiedClaimAgeOverNN {

    private static final long serialVersionUID = -6005690209140831298L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocVerifiedClaimAgeOverNN.class);

    /**
     * Constructor to initialize MdocClaimAgeOverNN from a ClaimBoolean
     *
     * @param value {@link VerifiedClaimBoolean}
     */
    public MdocVerifiedClaimAgeOverNN(VerifiedClaimBoolean value) {
        super(value.getName(), value.getNamespace(), value.getBooleanValue(), value.isSelectivelyDisclosable(), value.getParent());
    }
    
    @Override
    public Integer getAge() {
        String name = getName();
        String nnAge = Utils.substringAfter(name, ISO180135Headers.AGE_OVER_NN);
        if (Utils.isStringDigits(nnAge)) {
            return Integer.parseInt(nnAge);
        }
        LOG.warn("Unable to determine age from the header with name '{}'!", name);
        return null;
    }
    
}
