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
package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * DTO representing a custom claim's value
 *
 */
public class ClaimValueDTO implements Serializable {

    private static final long serialVersionUID = -1184176830219560884L;

    /** String value */
    private String stringValue;

    /** Numeric value */
    private Number numberValue;

    /** Boolean value */
    private Boolean booleanValue;

    /** Date value */
    private Date dateValue;

    /** Binary value */
    private byte[] binaryValue;

    /** Array value represented as a list of claims */
    private List<ClaimDTO> arrayValue;

    /** Object value represented as a list of named claims */
    private List<ClaimDTO> objectValue;

    /**
     * Default constructor
     */
    public ClaimValueDTO() {
        // empty
    }

    /**
     * Constructor with String as a value
     *
     * @param stringValue {@link String}
     */
    public ClaimValueDTO(String stringValue) {
        this.stringValue = stringValue;
    }

    /**
     * Constructor with Number as a value
     *
     * @param numberValue {@link Number}
     */
    public ClaimValueDTO(Number numberValue) {
        this.numberValue = numberValue;
    }

    /**
     * Constructor with Boolean as a value
     *
     * @param booleanValue {@link Boolean}
     */
    public ClaimValueDTO(Boolean booleanValue) {
        this.booleanValue = booleanValue;
    }

    /**
     * Constructor with Date as a value
     *
     * @param dateValue {@link Date}
     */
    public ClaimValueDTO(Date dateValue) {
        this.dateValue = dateValue;
    }

    /**
     * Constructor with byte array as a value
     *
     * @param binaryValue byte array
     */
    public ClaimValueDTO(byte[] binaryValue) {
        this.binaryValue = binaryValue;
    }

    /**
     * Gets the string value
     *
     * @return {@link String}
     */
    public String getStringValue() {
        return stringValue;
    }

    /**
     * Sets the string value
     *
     * @param stringValue {@link String}
     */
    public void setStringValue(String stringValue) {
        this.stringValue = stringValue;
    }

    /**
     * Gets the numeric value
     *
     * @return {@link Number}
     */
    public Number getNumberValue() {
        return numberValue;
    }

    /**
     * Sets the numeric value
     *
     * @param numberValue {@link Number}
     */
    public void setNumberValue(Number numberValue) {
        this.numberValue = numberValue;
    }

    /**
     * Gets the boolean value
     *
     * @return {@link Boolean}
     */
    public Boolean getBooleanValue() {
        return booleanValue;
    }

    /**
     * Sets the boolean value
     *
     * @param booleanValue {@link Boolean}
     */
    public void setBooleanValue(Boolean booleanValue) {
        this.booleanValue = booleanValue;
    }

    /**
     * Gets the date value
     *
     * @return {@link Date}
     */
    public Date getDateValue() {
        return dateValue;
    }

    /**
     * Sets the date value
     *
     * @param dateValue {@link Date}
     */
    public void setDateValue(Date dateValue) {
        this.dateValue = dateValue;
    }

    /**
     * Gets the binary value
     *
     * @return byte[]
     */
    public byte[] getBinaryValue() {
        return binaryValue;
    }

    /**
     * Sets the binary value
     *
     * @param binaryValue byte[]
     */
    public void setBinaryValue(byte[] binaryValue) {
        this.binaryValue = binaryValue;
    }

    /**
     * Gets the array value
     *
     * @return {@link List<ClaimDTO>}
     */
    public List<ClaimDTO> getArrayValue() {
        return arrayValue;
    }

    /**
     * Sets the array value
     *
     * @param arrayValue {@link List<ClaimDTO>}
     */
    public void setArrayValue(List<ClaimDTO> arrayValue) {
        this.arrayValue = arrayValue;
    }

    /**
     * Gets the object value
     *
     * @return {@link List<ClaimDTO>}
     */
    public List<ClaimDTO> getObjectValue() {
        return objectValue;
    }

    /**
     * Sets the object value
     *
     * @param objectValue {@link List<ClaimDTO>}
     */
    public void setObjectValue(List<ClaimDTO> objectValue) {
        this.objectValue = objectValue;
    }

    @Override
    public String toString() {
        return "ClaimValueDTO [" +
                "stringValue='" + stringValue + '\'' +
                ", numberValue=" + numberValue +
                ", booleanValue=" + booleanValue +
                ", dateValue=" + dateValue +
                ", binaryValue=" + Arrays.toString(binaryValue) +
                ", arrayValue=" + arrayValue +
                ", objectValue=" + objectValue +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        ClaimValueDTO that = (ClaimValueDTO) object;
        return Objects.equals(stringValue, that.stringValue)
                && Objects.equals(numberValue, that.numberValue)
                && Objects.equals(booleanValue, that.booleanValue)
                && Objects.equals(dateValue, that.dateValue)
                && Arrays.equals(binaryValue, that.binaryValue)
                && Objects.equals(arrayValue, that.arrayValue)
                && Objects.equals(objectValue, that.objectValue);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(stringValue);
        result = 31 * result + Objects.hashCode(numberValue);
        result = 31 * result + Objects.hashCode(booleanValue);
        result = 31 * result + Objects.hashCode(dateValue);
        result = 31 * result + Arrays.hashCode(binaryValue);
        result = 31 * result + Objects.hashCode(arrayValue);
        result = 31 * result + Objects.hashCode(objectValue);
        return result;
    }

}