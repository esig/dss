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
package eu.europa.esig.dss.attestation.common.creation.claim;

/**
 * Abstract implementation of an EAA Claim
 */
public abstract class AbstractAttestationClaim implements AttestationClaim {

    private static final long serialVersionUID = -1092016241135884116L;

    /** Name of the claim element */
    private final String name;

    /** Value of the claim element */
    private final Object value;

    /**
     * Constructor with the value and claim name
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the value of the claim
     */
    protected AbstractAttestationClaim(final String name, final Object value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Gets the claim name
     *
     * @return {@link String}
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * Gets the value
     *
     * @return {@link Object} the value
     */
    @Override
    public Object getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "AbstractEAAClaim [" +
                "name='" + name + '\'' +
                ", value=" + value +
                ']';
    }

}

