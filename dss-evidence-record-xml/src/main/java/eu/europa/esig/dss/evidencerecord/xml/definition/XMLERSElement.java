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
package eu.europa.esig.dss.evidencerecord.xml.definition;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * XMLERS elements
 *
 */
public enum XMLERSElement implements DSSElement {

    /** EvidenceRecord */
    EVIDENCE_RECORD("EvidenceRecord"),

    /** EncryptionInformation */
    ENCRYPTION_INFORMATION("EncryptionInformation"),

    /** EncryptionInformationType */
    ENCRYPTION_INFORMATION_TYPE("EncryptionInformationType"),

    /** EncryptionInformationValue */
    ENCRYPTION_INFORMATION_VALUE("EncryptionInformationValue"),

    /** ArchiveTimeStampSequence */
    ARCHIVE_TIME_STAMP_SEQUENCE("ArchiveTimeStampSequence"),

    /** ArchiveTimeStampChain */
    ARCHIVE_TIME_STAMP_CHAIN("ArchiveTimeStampChain"),

    /** DigestMethod */
    DIGEST_METHOD("DigestMethod"),

    /** CanonicalizationMethod */
    CANONICALIZATION_METHOD("CanonicalizationMethod"),

    /** EncryptionInformation */
    ARCHIVE_TIME_STAMP("ArchiveTimeStamp"),

    /** HashTree */
    HASH_TREE("HashTree"),

    /** TimeStamp */
    TIME_STAMP("TimeStamp"),

    /** Attributes */
    ATTRIBUTES("Attributes"),

    /** TimeStampToken */
    TIME_STAMP_TOKEN("TimeStampToken"),

    /** CryptographicInformationList */
    CRYPTOGRAPHIC_INFORMATION_LIST("CryptographicInformationList"),

    /** CryptographicInformation */
    CRYPTOGRAPHIC_INFORMATION("CryptographicInformation"),

    /** Sequence */
    SEQUENCE("Sequence"),

    /** DigestValue */
    DIGEST_VALUE("DigestValue"),

    /** Attribute */
    ATTRIBUTE("Attribute"),

    /** SupportingInformationList */
    SUPPORTING_INFORMATION_LIST("SupportingInformationList"),

    /** SupportingInformation */
    SUPPORTING_INFORMATION("SupportingInformation");

    /** Namespace */
    private final DSSNamespace namespace;

    /** The tag name */
    private final String tagName;

    /**
     * Default constructor
     *
     * @param tagName {@link String}
     */
    XMLERSElement(String tagName) {
        this.tagName = tagName;
        this.namespace = XMLERSNamespace.XMLERS;
    }

    @Override
    public DSSNamespace getNamespace() {
        return namespace;
    }

    @Override
    public String getTagName() {
        return tagName;
    }

    @Override
    public String getURI() {
        return namespace.getUri();
    }

    @Override
    public boolean isSameTagName(String value) {
        return tagName.equals(value);
    }

}
