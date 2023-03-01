/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class is used to generate a deterministic reference identifier
 *
 */
public class ReferenceIdProvider {

    /** The signature parameters used to create the signature */
    private XAdESSignatureParameters signatureParameters;

    /**
     * id-prefix for ds:Reference element
     * Default : "r-"
     */
    private String referenceIdPrefix = "r";

    /** Internal reference id counter */
    private int index;

    /**
     * Default constructor
     */
    public ReferenceIdProvider() {
        // empty
    }

    /**
     * Sets signature parameters to build a deterministic identifier
     *
     * @param signatureParameters {@link XAdESSignatureParameters}
     */
    public void setSignatureParameters(XAdESSignatureParameters signatureParameters) {
        this.signatureParameters = signatureParameters;
    }

    /**
     * Sets the reference id prefix to be used on reference creation
     *
     * @param referenceIdPrefix {@link String} id prefix to use for references
     */
    public void setReferenceIdPrefix(String referenceIdPrefix) {
        if (Utils.isStringBlank(referenceIdPrefix)) {
            throw new IllegalArgumentException("The reference id prefix cannot be blank!");
        }
        this.referenceIdPrefix = referenceIdPrefix;
    }

    /**
     * This method returns the following signature reference identifier
     *
     * @return {@link String}
     */
    public String getReferenceId() {
        increaseIndex();

        final StringBuilder referenceId = new StringBuilder();
        referenceId.append(referenceIdPrefix);
        referenceId.append("-");
        if (signatureParameters != null) {
            referenceId.append(signatureParameters.getDeterministicId());
            referenceId.append("-");
        }
        referenceId.append(index);
        return referenceId.toString();
    }

    private void increaseIndex() {
        ++index;
    }

}
