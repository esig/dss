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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * This class contains common methods for ASiC filename factory.
 *
 */
public abstract class AbstractASiCFilenameFactory implements Serializable {

    private static final long serialVersionUID = 7868238704099416943L;

    /**
     * This method returns the next available suffix (i.e. number) for a new file entry across given document names.
     *
     * Ex.: For provided two signature documents, the method will return "003" suffix,
     * to be used for a signature file creation with a name "META-INF/signature003.xml".
     *
     * @param nameTemplate {@link String} defining the String template of the final name
     * @param existingDocumentNames a list of {@link String} document names forbidden for usage
     * @return {@link String} available document name suffix
     */
    protected String getNextAvailableDocumentName(String nameTemplate, Collection<String> existingDocumentNames) {
        // Use set to exclude duplicated names
        return getDocumentNameRecursively(nameTemplate, new HashSet<>(existingDocumentNames));
    }

    private String getDocumentNameRecursively(String nameTemplate, Collection<String> existingDocumentNames) {
        int number = existingDocumentNames.size() + 1;
        String numberStr = String.valueOf(number);
        String zeroPad = "000";
        String candidateSuffix = numberStr.length() < zeroPad.length() ?
                zeroPad.substring(numberStr.length()) + numberStr : numberStr; // 2 -> 002
        String candidateName = nameTemplate.replace("001", candidateSuffix);
        if (!isAvailableName(candidateName, existingDocumentNames)) {
            existingDocumentNames = new ArrayList<>(existingDocumentNames); // to list to allow increment
            existingDocumentNames.add(candidateName); // increase the amount of entries within the list
            return getDocumentNameRecursively(nameTemplate, existingDocumentNames);
        }
        return candidateName;
    }

    /**
     * This method verifies whether the {@code filename} is not present within {@code restrictedNames}
     *
     * @param filename {@link String} to verify
     * @param restrictedNames a list of {@link String} taken filenames
     * @return TRUE if the {@code filename} is available (free) for usage, FALSE otherwise
     */
    protected boolean isAvailableName(String filename, Collection<String> restrictedNames) {
        return !restrictedNames.contains(filename);
    }

    /**
     * This method is used to append a "META-INF/" string to the filename, when required.
     *
     * @param filename {@link String} represented a document filename to be present within "META-INF/" folder
     * @return {@link String}
     */
    protected String getWithMetaInfFolder(String filename) {
        if (!filename.startsWith(ASiCUtils.META_INF_FOLDER)) {
            filename = ASiCUtils.META_INF_FOLDER + filename;
        }
        return filename;
    }

    /**
     * This method is used to verify whether the provided {@code asicContent}
     * contains all the required information for a new filename determination
     *
     * @param asicContent {@link ASiCContent} to be verified
     */
    protected void assertASiCContentIsValid(ASiCContent asicContent) {
        Objects.requireNonNull(asicContent, "ASiCContent shall be provided!");
        Objects.requireNonNull(asicContent.getContainerType(), "Type of ASiC Container shall be defined!");
        if (ASiCContainerType.ASiC_S != asicContent.getContainerType() &&
                ASiCContainerType.ASiC_E != asicContent.getContainerType()) {
            throw new IllegalArgumentException("The type of the ASiCContent shall be one of ASiC-S or ASiC-E!");
        }
    }

    /**
     * This method verifies whether the given {@code filename} represents a valid document name within a container
     *
     * @param filename {@link String} filename to check
     * @param documentsOfType list of {@link DSSDocument} of the same type as a creating document
     */
    protected void assertFilenameValid(String filename, List<DSSDocument> documentsOfType) {
        if (!isAvailableName(filename, DSSUtils.getDocumentNames(documentsOfType))) {
            throw new IllegalInputException(String.format("The filename '%s' cannot be used, " +
                    "as a document of the same name is already present within the container!", filename));
        }
    }

    /**
     * This method returns a valid data package filename
     *
     * @param dataPackageFilename {@link String} defined data package filename
     * @param asicContent {@link ASiCContent}
     * @return {@link String} data package filename
     */
    protected String getValidDataPackageFilename(String dataPackageFilename, ASiCContent asicContent) {
        assertFilenameValid(dataPackageFilename, asicContent.getSignedDocuments());
        if (dataPackageFilename.contains("/")) {
            throw new IllegalArgumentException("A data package file within ASiC container shall be on the root level!");
        } else if (!dataPackageFilename.toLowerCase().endsWith(".zip")) {
            throw new IllegalArgumentException("A data package filename within ASiC container shall ends with '.zip'!");
        }
        return dataPackageFilename;
    }

}
