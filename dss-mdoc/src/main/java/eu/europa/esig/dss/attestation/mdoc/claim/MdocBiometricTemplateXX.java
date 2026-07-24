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
import eu.europa.esig.dss.model.attestation.claim.ClaimBiometricTemplateXX;
import eu.europa.esig.dss.model.attestation.claim.ClaimBoolean;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.utils.Utils;

/**
 * Mdoc implementation of a biometric template as defined in "7.2.6 Biometric template" of ISO/IEC 18013-5.
 *
 */
public class MdocBiometricTemplateXX extends ClaimByteString implements ClaimBiometricTemplateXX {

    private static final long serialVersionUID = -6005690209140831298L;

    /**
     * Constructor to initialize MdocClaimAgeOverNN from a ClaimByteString
     *
     * @param value {@link ClaimBoolean}
     */
    public MdocBiometricTemplateXX(ClaimByteString value) {
        super(value.getName(), value.getNamespace(), value.getBinaryValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public String getType() {
        String name = getName();
        return Utils.substringAfter(name, ISO180135Headers.BIOMETRIC_TEMPLATE_XX);
    }

}
