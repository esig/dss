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
import java.util.Objects;

/**
 * Represents an "biometric_template_NN" claim parameter
 *
 */
public class BiometricTemplateNNDTO implements Serializable {

    private static final long serialVersionUID = -6262181747635128573L;

    /** Type name of the biometric template */
    private String type;

    /** Data content of the biometric template */
    private byte[] data;

    /**
     * Default constructor
     */
    public BiometricTemplateNNDTO() {
        // empty
    }

    /**
     * Returns the type
     *
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the type
     *
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Returns the data
     *
     * @return the data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Sets the data
     *
     * @param data the data to set
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "BiometricTemplateNNDTO [" +
                "type='" + type + '\'' +
                ", data=" + Arrays.toString(data) +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        BiometricTemplateNNDTO that = (BiometricTemplateNNDTO) object;
        return Objects.equals(type, that.type)
                && Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(type);
        result = 31 * result + Arrays.hashCode(data);
        return result;
    }

}
