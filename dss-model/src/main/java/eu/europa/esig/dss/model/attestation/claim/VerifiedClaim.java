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
package eu.europa.esig.dss.model.attestation.claim;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Defines a claim that may be made selectively disclosable.
 * The object is used on an annotation validation.
 *
 */
public interface VerifiedClaim extends Serializable {

    /**
     * Gets the claim name
     *
     * @return {@link String}
     */
    String getName();

    /**
     * Gets whether the claim was made selectively disclosable and its value has been obtained from a provided disclosure
     *
     * @return whether the claim's value has been obtained from a disclosure
     */
    boolean isSelectivelyDisclosable();

    /**
     * Gets the origin namespace of the claim (NOTE: used in mdoc)
     *
     * @return {@link String}
     */
    String getNamespace();

    /**
     * Gets parent claim, when applicable (e.g. for claims nested within a map or an array)
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getParent();

    /**
     * Gets the value as list.
     * If the value is null or not of a list type, returns null
     *
     * @return {@link List}
     */
    List<VerifiedClaim> getListValue();

    /**
     * Gets the value as binaries.
     * If the value is null or not of binaries type, returns null
     *
     * @return byte array
     */
    byte[] getBinaryValue();

    /**
     * Gets the value as boolean.
     * If the value is null or not of a boolean type, returns null
     *
     * @return {@link Boolean}
     */
    Boolean getBooleanValue();

    /**
     * Gets the value as date.
     * If the value is null or not of a date type, returns null
     *
     * @return {@link Date}
     */
    Date getDateValue();

    /**
     * Gets the value as a map.
     * If the value is null or not of a map type, returns null
     *
     * @return {@link Map}
     */
    Map<String, VerifiedClaim> getMapValue();

    /**
     * Gets the value as a number.
     * If the value is null or not of a number type, returns null
     *
     * @return {@link Number}
     */
    Number getNumberValue();

    /**
     * Gets the value as a string.
     * If the value is null or not of a string type, returns null
     *
     * @return {@link String}
     */
    String getStringValue();

    /**
     * Gets whether the claim value is of String type
     *
     * @return TRUE if the value is of String type, FALSE otherwise
     */
    boolean isStringValueType();

    /**
     * Gets whether the claim value is of Binary type
     *
     * @return TRUE if the value is of Binary type, FALSE otherwise
     */
    boolean isBinaryValueType();

    /**
     * Gets whether the claim value is of Boolean type
     *
     * @return TRUE if the value is of Boolean type, FALSE otherwise
     */
    boolean isBooleanValueType();

    /**
     * Gets whether the claim value is of Number type
     *
     * @return TRUE if the value is of Number type, FALSE otherwise
     */
    boolean isNumberValueType();

    /**
     * Gets whether the claim value is of Date type
     *
     * @return TRUE if the value is of Date type, FALSE otherwise
     */
    boolean isDateValueType();

    /**
     * Gets whether the claim value is of Array type
     *
     * @return TRUE if the value is of Array type, FALSE otherwise
     */
    boolean isArrayValueType();

    /**
     * Gets whether the claim value is of Map type
     *
     * @return TRUE if the value is of Map type, FALSE otherwise
     */
    boolean isMapValueType();

    /**
     * Gets whether the claim value is of Null type
     *
     * @return TRUE if the value is of Null type, FALSE otherwise
     */
    boolean isNullValueType();

    /**
     * Gets whether the claim provides an integrity validation material for the other claim, implementation specific
     *
     * @return TRUE if the claim provides an integrity validation material for the other claim, FALSE otherwise
     */
    boolean isSubresourceIntegrityType();

    /**
     * Gets whether the value of the claim is null or empty
     *
     * @return TRUE whether the value of the claim is null or empty, FALSE otherwise
     */
    boolean isNullOrEmpty();

    /**
     * Converts the claim's value to its corresponding string representation
     *
     * @return {@link String}
     */
    String getValueAsString();

}
