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
package eu.europa.esig.dss.attestation.mdoc.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Represents a DrivingPrivilege structure as defined in ISO/IEC 18013-5 "7.2.4 Categories of vehicles/restrictions/conditions".
 *
 */
public class MdocDrivingPrivilege implements Serializable {

    private static final long serialVersionUID = 6153862012367616220L;

    /** Vehicle category code as per ISO/IEC 18013-1 Annex B */
    private final String vehicleCategoryCode;

    /** Date of issue encoded as full-date */
    private Date issueDate;

    /** Date of expiry encoded as full-date */
    private Date expiryDate;

    /** Array of code info */
    private List<Code> codes;

    /**
     * Default constructor
     *
     * @param vehicleCategoryCode {@link String} vehicle category code as per ISO/IEC 18013-1 Annex B
     */
    public MdocDrivingPrivilege(final String vehicleCategoryCode) {
        this.vehicleCategoryCode = vehicleCategoryCode;
    }

    /**
     * Gets the vehicle category code
     *
     * @return {@link String}
     */
    public String getVehicleCategoryCode() {
        return vehicleCategoryCode;
    }

    /**
     * Gets the issue date
     *
     * @return {@link Date}
     */
    public Date getIssueDate() {
        return issueDate;
    }

    /**
     * Sets date of issue
     *
     * @param issueDate {@link Date}
     */
    public void setIssueDate(Date issueDate) {
        this.issueDate = issueDate;
    }

    /**
     * Gets the expiry date
     *
     * @return {@link Date}
     */
    public Date getExpiryDate() {
        return expiryDate;
    }

    /**
     * Sets date of expiry
     *
     * @param expiryDate {@link Date}
     */
    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    /**
     * Gets a list of code info
     *
     * @return a list of {@link Code}s
     */
    public List<Code> getCodes() {
        return codes;
    }

    /**
     * Adds a code to the array of code info
     *
     * @param code {@link Code}
     */
    public void addCode(Code code) {
        if (codes == null) {
            this.codes = new ArrayList<>();
        }
        codes.add(code);
    }

    /**
     * Adds a code with code to the array of code info
     *
     * @param code code as per ISO/IEC 18013-2 Annex A
     */
    public void addCode(String code) {
        addCode(new Code(code));
    }

    /**
     * Adds a code with code, sign and value to the array of code info
     *
     * @param code code as per ISO/IEC 18013-2 Annex A
     * @param sign sign as per ISO/IEC 18013-2 Annex A
     * @param value value as per ISO/IEC 18013-2 Annex A
     */
    public void addCode(String code, String sign, String value) {
        addCode(new Code(code, sign, value));
    }

    /**
     * Represents a Code structure as defined in ISO/IEC 18013-5 "7.2.4 Categories of vehicles/restrictions/conditions".
     */
    public static class Code implements Serializable {

        private static final long serialVersionUID = -2322614345103093927L;

        /** Code as per ISO/IEC 18013-2 Annex A */
        private final String code;

        /** Sign as per ISO/IEC 18013-2 Annex A */
        private final String sign;

        /** Value as per ISO/IEC 18013-2 Annex A */
        private final String value;

        /**
         * Constructor with code definition only
         *
         * @param code code as per ISO/IEC 18013-2 Annex A
         */
        public Code(final String code) {
            this(code, null, null);
        }

        /**
         * Constructor with code, sign and value definitions
         *
         * @param code code as per ISO/IEC 18013-2 Annex A
         * @param sign sign as per ISO/IEC 18013-2 Annex A
         * @param value value as per ISO/IEC 18013-2 Annex A
         */
        public Code(final String code, final String sign, final String value) {
            this.code = code;
            this.sign = sign;
            this.value = value;
        }

        /**
         * Gets the code
         *
         * @return {@link String}
         */
        public String getCode() {
            return code;
        }

        /**
         * Gets the sign
         *
         * @return {@link String}
         */
        public String getSign() {
            return sign;
        }

        /**
         * Gets the value
         *
         * @return {@link String}
         */
        public String getValue() {
            return value;
        }

        @Override
        public String toString() {
            return "Code [" +
                    "code='" + code + '\'' +
                    ", sign='" + sign + '\'' +
                    ", value='" + value + '\'' +
                    ']';
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) return true;
            if (object == null || getClass() != object.getClass()) return false;

            Code code1 = (Code) object;
            return Objects.equals(code, code1.code)
                    && Objects.equals(sign, code1.sign)
                    && Objects.equals(value, code1.value);
        }

        @Override
        public int hashCode() {
            int result = Objects.hashCode(code);
            result = 31 * result + Objects.hashCode(sign);
            result = 31 * result + Objects.hashCode(value);
            return result;
        }

    }

    @Override
    public String toString() {
        return "MdocDrivingPrivilege [" +
                "vehicleCategoryCode='" + vehicleCategoryCode + '\'' +
                ", issueDate=" + issueDate +
                ", expiryDate=" + expiryDate +
                ", codes=" + codes +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        MdocDrivingPrivilege that = (MdocDrivingPrivilege) object;
        return Objects.equals(vehicleCategoryCode, that.vehicleCategoryCode)
                && Objects.equals(issueDate, that.issueDate)
                && Objects.equals(expiryDate, that.expiryDate)
                && Objects.equals(codes, that.codes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(vehicleCategoryCode);
        result = 31 * result + Objects.hashCode(issueDate);
        result = 31 * result + Objects.hashCode(expiryDate);
        result = 31 * result + Objects.hashCode(codes);
        return result;
    }

}
