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
package eu.europa.esig.dss;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;
import java.util.List;

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

}
