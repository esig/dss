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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.CommitmentType;

/**
 * This class provides a basic implementation of {@code CommitmentType} providing a possibility
 * to create a customized CommitmentType signed property.
 *
 */
public class CommonCommitmentType extends CommonObjectIdentifier implements CommitmentType {

    private static final long serialVersionUID = 8102201740643836228L;

    /**
     * Defines signed data objects referenced by the current CommitmentType
     * Use : OPTIONAL
     */
    private String[] signedDataObjects;

    /**
     * Defines custom CommitmentTypeQualifiers list
     * Use : OPTIONAL
     */
    private CommitmentQualifier[] commitmentTypeQualifiers;

    /**
     * Default constructor instantiating object with null values
     */
    public CommonCommitmentType() {
        // empty
    }

    /**
     * Gets references to signed data objects for the current CommitmentType
     *
     * @return array of {@link String}s
     */
    public String[] getSignedDataObjects() {
        return signedDataObjects;
    }

    /**
     * Sets signed data objects referenced by the current CommitmentType.
     *
     * When CommitmentType is made for a subset of signed data objects, each element of the array shall refer
     * one ds:Reference element within the ds:SignedInfo element or within a signed ds:Manifest element.
     * When CommitmentType is made for all signed data objects, the array shall be:
     * - empty (default), then AllSignedDataObjects element will be created; or
     * - contain references to all signed data objects (one ObjectReference will be created for each).
     *
     * Use : OPTIONAL (XAdES only)
     *
     * @param signedDataObjects array of {@link String}s
     */
    public void setSignedDataObjects(String... signedDataObjects) {
        this.signedDataObjects = signedDataObjects;
    }

    /**
     * Gets custom CommitmentTypeQualifiers List
     *
     * @return array of {@link DSSDocument}s
     */
    public CommitmentQualifier[] getCommitmentTypeQualifiers() {
        return commitmentTypeQualifiers;
    }

    /**
     * Sets custom CommitmentTypeQualifiers List.
     *
     * Use : OPTIONAL
     *
     * @param commitmentTypeQualifiers array of {@link CommitmentQualifier}s representing content
     *                                 of the CommitmentTypeQualifier element
     */
    public void setCommitmentTypeQualifiers(CommitmentQualifier... commitmentTypeQualifiers) {
        this.commitmentTypeQualifiers = commitmentTypeQualifiers;
    }

}
