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
package eu.europa.esig.dss.model.x509.extension;

import java.math.BigInteger;

/**
 * Represents a general subtree element (see "4.2.1.10. Name Constraints" of RFC 5280)
 *
 */
public class GeneralSubtree extends GeneralName {

    private static final long serialVersionUID = 4297563579116497603L;

    /** MUST be 0 */
    private BigInteger minimum;

    /** MUST be absent */
    private BigInteger maximum;

    /**
     * Default constructor
     */
    public GeneralSubtree() {
        // empty
    }

    /**
     * Gets the minimum constraint value
     *
     * @return {@link BigInteger}
     */
    public BigInteger getMinimum() {
        return minimum;
    }

    /**
     * Sets the minimum constraint value
     *
     * @param minimum {@link BigInteger}
     */
    public void setMinimum(BigInteger minimum) {
        this.minimum = minimum;
    }

    /**
     * Gets the maximum constraint value
     *
     * @return {@link BigInteger}
     */
    public BigInteger getMaximum() {
        return maximum;
    }

    /**
     * Sets the maximum constraint value
     *
     * @param maximum {@link BigInteger}
     */
    public void setMaximum(BigInteger maximum) {
        this.maximum = maximum;
    }

}
