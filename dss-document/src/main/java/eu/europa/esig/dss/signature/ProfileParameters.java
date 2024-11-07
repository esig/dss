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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the signature generation.
 *
 */
public class ProfileParameters implements Serializable {

    private static final long serialVersionUID = -8281291690615571695L;

    /**
     * The id created in a deterministic way based on the filled parameters to use in the signature file
     */
    private String deterministicId;

    /** Cached detached contents (used for DETACHED signature creation or/and ASiC containers signing) */
    private List<DSSDocument> detachedContents;

    /**
     * Default constructor instantiating object with null values
     */
    public ProfileParameters() {
        // empty
    }

    /**
     * Gets the deterministic id
     *
     * @return {@link String}
     */
    public String getDeterministicId() {
        return deterministicId;
    }

    /**
     * Sets the deterministic id
     *
     * @param deterministicId {@link String}
     */
    public void setDeterministicId(String deterministicId) {
        this.deterministicId = deterministicId;
    }

    /**
     * Gets the detached contents
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets the detached contents
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    @Override
    public String toString() {
        return "ProfileParameters{" +
                "deterministicId='" + deterministicId + '\'' +
                ", detachedContents=" + detachedContents +
                '}';
    }

    @Override
    public int hashCode() {
        int result = deterministicId != null ? deterministicId.hashCode() : 0;
        result = 31 * result + (detachedContents != null ? detachedContents.hashCode() : 0);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProfileParameters)) return false;

        ProfileParameters that = (ProfileParameters) o;

        if (!Objects.equals(deterministicId, that.deterministicId))
            return false;
        return Objects.equals(detachedContents, that.detachedContents);
    }

}
