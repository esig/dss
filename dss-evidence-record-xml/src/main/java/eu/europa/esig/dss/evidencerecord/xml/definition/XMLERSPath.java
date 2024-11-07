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
package eu.europa.esig.dss.evidencerecord.xml.definition;

import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * XMLERS Paths
 */
public class XMLERSPath extends AbstractPath {

    /**
     * Default constructor
     */
    public XMLERSPath() {
        // empty
    }

    /**
     * "./ers:EvidenceRecord"
     */
    public static final String EVIDENCE_RECORD_PATH = fromCurrentPosition(XMLERSElement.EVIDENCE_RECORD);

    /**
     * "./ers:ArchiveTimeStampSequence"
     */
    public static final String ARCHIVE_TIME_STAMP_SEQUENCE_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP_SEQUENCE);

    /**
     * "./ers:ArchiveTimeStampSequence/ers:ArchiveTimeStampChain"
     */
    public static final String ARCHIVE_TIME_STAMP_CHAIN_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP_SEQUENCE, XMLERSElement.ARCHIVE_TIME_STAMP_CHAIN);

    /**
     * "./ers:ArchiveTimeStamp"
     */
    public static final String ARCHIVE_TIME_STAMP_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP);

    /**
     * "./ers:DigestMethod"
     */
    public static final String DIGEST_METHOD_PATH = fromCurrentPosition(XMLERSElement.DIGEST_METHOD);

    /**
     * "./ers:CanonicalizationMethod"
     */
    public static final String CANONICALIZATION_METHOD_PATH = fromCurrentPosition(XMLERSElement.CANONICALIZATION_METHOD);

    /**
     * "./ers:HashTree/ers:Sequence"
     */
    public static final String HASH_TREE_SEQUENCE_PATH = fromCurrentPosition(XMLERSElement.HASH_TREE, XMLERSElement.SEQUENCE);

    /**
     * "./ers:DigestValue"
     */
    public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XMLERSElement.DIGEST_VALUE);

    /**
     * "./ers:TimeStamp"
     */
    public static final String TIME_STAMP_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP);

    /**
     * "./ers:TimeStamp/ers:TimeStampToken"
     */
    public static final String TIME_STAMP_TOKEN_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP, XMLERSElement.TIME_STAMP_TOKEN);

    /**
     * "./ers:TimeStamp/ers:CryptographicInformationList/ers:CryptographicInformation"
     */
    public static final String CRYPTOGRAPHIC_INFORMATION_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP, XMLERSElement.CRYPTOGRAPHIC_INFORMATION_LIST, XMLERSElement.CRYPTOGRAPHIC_INFORMATION);

    /**
     * Returns a namespace of the XMLERS paths
     *
     * @return {@link DSSNamespace}
     */
    public DSSNamespace getNamespace() {
        return XMLERSNamespace.XMLERS;
    }

}
