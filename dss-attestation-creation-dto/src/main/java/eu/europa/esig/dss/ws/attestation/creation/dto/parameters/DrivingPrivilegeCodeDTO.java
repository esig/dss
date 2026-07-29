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
import java.util.Objects;

/**
 * DTO representing a code of a driving privilege as per ISO/IEC 18013-5
 *
 */
public class DrivingPrivilegeCodeDTO implements Serializable {

    private static final long serialVersionUID = 6276269021612834847L;

    /** Code as per ISO/IEC 18013-2 Annex A */
    private String code;

    /** Sign as per ISO/IEC 18013-2 Annex A */
    private String sign;

    /** Value as per ISO/IEC 18013-2 Annex A */
    private String value;

    /**
     * Default constructor
     */
    public DrivingPrivilegeCodeDTO() {
        // empty
    }

    /**
     * Returns the code
     *
     * @return the code
     */
    public String getCode() {
        return code;
    }

    /**
     * Sets the code
     *
     * @param code the code to set
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * Returns the sign
     *
     * @return the sign
     */
    public String getSign() {
        return sign;
    }

    /**
     * Sets the sign
     *
     * @param sign the sign to set
     */
    public void setSign(String sign) {
        this.sign = sign;
    }

    /**
     * Returns the value
     *
     * @return the value
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the value
     *
     * @param value the value to set
     */
    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "DrivingPrivilegeCodeDTO [" +
                "code='" + code + '\'' +
                ", sign='" + sign + '\'' +
                ", value='" + value + '\'' +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        DrivingPrivilegeCodeDTO codeDTO = (DrivingPrivilegeCodeDTO) object;
        return Objects.equals(code, codeDTO.code)
                && Objects.equals(sign, codeDTO.sign)
                && Objects.equals(value, codeDTO.value);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(code);
        result = 31 * result + Objects.hashCode(sign);
        result = 31 * result + Objects.hashCode(value);
        return result;
    }

}
