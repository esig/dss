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
package eu.europa.esig.dss.pdfa;

import java.util.Collection;

/**
 * This class represents a validation result against PDF/A specification
 *
 */
public class PDFAValidationResult {

    /** Assumed PDF/A profile for the document */
    private String profileId;

    /** Defines whether the document is compliant to the identified {@code profileId} */
    private boolean compliant;

    /** Collection of error messages returned by the validator, when validation failed */
    private Collection<String> errorMessages;

    /**
     * Default constructor
     */
    public PDFAValidationResult() {
        // empty
    }

    /**
     * Gets PDF/A profile Id
     *
     * @return {@link String}
     */
    public String getProfileId() {
        return profileId;
    }

    /**
     * Sets the profile Id
     *
     * @param profileId {@link String}
     */
    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    /**
     * Gets whether the validated document is compliant according to the returned profile Id
     *
     * @return TRUE of the document is a compliant PDF/A, FALSE otherwise
     */
    public boolean isCompliant() {
        return compliant;
    }

    /**
     * Sets whether the document is compliant to the identified profile Id
     *
     * @param compliant whether the document is a compliant PDF/A
     */
    public void setCompliant(boolean compliant) {
        this.compliant = compliant;
    }

    /**
     * Gets a list of error messages returned by the validator
     *
     * @return a collection of {@link String}s
     */
    public Collection<String> getErrorMessages() {
        return errorMessages;
    }

    /**
     * Sets a collection of error messages returned by the validator
     *
     * @param errorMessages a collection of {@link String} error messages
     */
    public void setErrorMessages(Collection<String> errorMessages) {
        this.errorMessages = errorMessages;
    }

}
