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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

/**
 * This class provides a basic implementation of {@code CommitmentType} providing a possibility
 * to create a customized CommitmentType signed property.
 *
 */
public class CommonCommitmentType implements CommitmentType {

    private static final long serialVersionUID = 8102201740643836228L;

    /**
     * Defines URI of the CommitmentType (used in XAdES, JAdES).
     * Use : CONDITIONAL (should be present in XAdES, JAdES).
     */
    private String uri;

    /**
     * Defines OID identifier of the CommitmentType (used in CAdES, PAdES, JAdES).
     * Use : CONDITIONAL (shall be present in CAdES, PAdES. May be present in XAdES, JAdES).
     */
    private String oid;

    /**
     * Defines the type of URI when an OID is provided as a URI (used in XAdES, see ETSI EN 319 132-1 for more details).
     * Use : CONDITIONAL (may be present in XAdES).
     */
    private ObjectIdentifierQualifier qualifier;

    /**
     * Contains a text describing the CommitmentType.
     * Use : OPTIONAL
     */
    private String description;

    /**
     * Contains arbitrary number of references pointing to further explanatory document about the CommitmentType.
     * Use : OPTIONAL
     */
    private String[] documentationReferences;

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
    }

    @Override
    public String getUri() {
        return uri;
    }

    /**
     * Sets URI identifying the CommitmentType
     *
     * Use : CONDITIONAL (should be present in XAdES, JAdES)
     *
     * @param uri {@link String}
     */
    public void setUri(String uri) {
        this.uri = uri;
    }

    @Override
    public String getOid() {
        return oid;
    }

    /**
     * Sets OID identifying the CommitmentType
     *
     * Use : CONDITIONAL (shall be present in CAdES, PAdES. May be present in XAdES, JAdES).
     *
     * Note : when using OID in XAdES, a Qualifier shall be defined within the method {@code setQualifier(qualifier)}.
     *        See EN 319 132-1 "5.1.2 The ObjectIdentifierType data type" for more information.
     *
     * @param oid {@link String}
     */
    public void setOid(String oid) {
        this.oid = oid;
    }

    @Override
    public ObjectIdentifierQualifier getQualifier() {
        return qualifier;
    }

    /**
     * Sets Qualifier defining the type of OID identifier used for CommitmentType.
     * See EN 319 132-1 "5.1.2 The ObjectIdentifierType data type" for more information.
     *
     * Use : CONDITIONAL (shall be present XAdES when using OID identifier, but not URI)
     *
     * Note : used only in XAdES
     *
     * @param qualifier {@link ObjectIdentifierQualifier}
     */
    public void setQualifier(ObjectIdentifierQualifier qualifier) {
        this.qualifier = qualifier;
    }

    @Override
    public String getDescription() {
        return description;
    }

    /**
     * Sets text describing the CommitmentType object.
     *
     * Use : OPTIONAL
     *
     * @param description {@link String}
     */
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String[] getDocumentationReferences() {
        return documentationReferences;
    }

    /**
     * Sets references pointing to a documentation describing the CommitmentType
     *
     * Use : OPTIONAL
     *
     * @param documentationReferences array of {@link String}s
     */
    public void setDocumentationReferences(String... documentationReferences) {
        this.documentationReferences = documentationReferences;
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
