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
 * Represents an "age_over_NN" claim parameter
 *
 */
public class AgeOverNNDTO implements Serializable {

    private static final long serialVersionUID = -7185379420422139031L;

    /** Age in years */
    private Integer age;

    /** Whether age of the attestation holder is equal or over the age value */
    private Boolean isOver;

    /**
     * Default constructor
     */
    public AgeOverNNDTO() {
        // empty
    }

    /**
     * Returns the age
     *
     * @return the age
     */
    public Integer getAge() {
        return age;
    }

    /**
     * Sets the age
     *
     * @param age the age to set
     */
    public void setAge(Integer age) {
        this.age = age;
    }

    /**
     * Returns whether the age is marked as over or equal
     *
     * @return whether the object is marked as over or equal
     */
    public Boolean getOver() {
        return isOver;
    }

    /**
     * Sets whether the age is marked as over or equal
     *
     * @param over whether the object is marked as over or equal
     */
    public void setOver(Boolean over) {
        isOver = over;
    }

    @Override
    public String toString() {
        return "AgeOverNNDTO [" +
                "age=" + age +
                ", isOver=" + isOver +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        AgeOverNNDTO that = (AgeOverNNDTO) object;
        return Objects.equals(age, that.age)
                && Objects.equals(isOver, that.isOver);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(age);
        result = 31 * result + Objects.hashCode(isOver);
        return result;
    }

}
