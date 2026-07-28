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
package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;

import java.util.ArrayList;
import java.util.List;

/**
 * This class contains information on the validation status of the ats-hash-index(-v3) attribute defined
 * within a timestamp of the archive-time-stamp-v3.
 *
 */
public class ArchiveTimestampHashIndexStatus {

    /**
     * Version of the ats-hash-index attribute
     */
    private ArchiveTimestampHashIndexVersion version;

    /**
     * Contains a list of error messages occurred during the timestamp's ats-hash-index-v3 attribute validation
     */
    private List<String> errorMessages;

    /**
     * Default constructor
     */
    public ArchiveTimestampHashIndexStatus() {
        // empty
    }

    /**
     * Gets the version of the ats-hash-index attribute used in the archive-time-stamp-v3
     *
     * @return {@link ArchiveTimestampHashIndexVersion}
     */
    public ArchiveTimestampHashIndexVersion getVersion() {
        return version;
    }

    /**
     * Sets the version of the ats-hash-index attribute used in the archive-time-stamp-v3
     *
     * @param version {@link ArchiveTimestampHashIndexVersion}
     */
    public void setVersion(ArchiveTimestampHashIndexVersion version) {
        this.version = version;
    }

    /**
     * Gets a list of validation errors occurred on a structural validation of the ats-hash-index(-v3) attribute,
     * when applicable
     *
     * @return a list of {@link String} error messages regarding the ats-hash-index-v3 attribute, when applicable
     */
    public List<String> getErrorMessages() {
        if (errorMessages == null) {
            errorMessages = new ArrayList<>();
        }
        return errorMessages;
    }

    /**
     * Adds a new error message in case of an issue on the ats-hash-index(-v3) attribute validation.
     *
     * @param errorMessage {@link String}
     */
    public void addErrorMessage(String errorMessage) {
        getErrorMessages().add(errorMessage);
    }

}
