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
package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractEvidenceRecordRenewalDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * This class builds digest for an RFC 6283 XMLERS evidence record's renewal
 *
 */
public class XMLEvidenceRecordRenewalDigestBuilder extends AbstractEvidenceRecordRenewalDigestBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(XMLEvidenceRecordRenewalDigestBuilder.class);

    /**
     * Canonicalization method to be used on processing of XML documents
     */
    private String canonicalizationMethod;

    /**
     * Creates an instance of {@code XMLEvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * XML evidence record {@code document}'s renewal, with a default SHA256 digest algorithm to be used on hash-tree
     * renewal computation (see note).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param document {@link DSSDocument}
     */
    public XMLEvidenceRecordRenewalDigestBuilder(final DSSDocument document) {
        this(new XmlEvidenceRecord(document));
    }

    /**
     * Creates an instance of {@code XMLEvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * XML evidence record {@code document}'s renewal, with the provided {@code digestAlgorithm} (see note below).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param document {@link DSSDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash-tree renewal hash computation
     */
    public XMLEvidenceRecordRenewalDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        this(new XmlEvidenceRecord(document), digestAlgorithm);
    }

    /**
     * Creates an instance of {@code XMLEvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * {@code XmlEvidenceRecord}'s renewal, with a default SHA256 digest algorithm to be used on hash-tree
     * renewal computation (see note).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param xmlEvidenceRecord {@link XmlEvidenceRecord}
     */
    public XMLEvidenceRecordRenewalDigestBuilder(final XmlEvidenceRecord xmlEvidenceRecord) {
        super(xmlEvidenceRecord);
    }

    /**
     * Creates an instance of {@code XMLEvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * {@code XmlEvidenceRecord}'s renewal, with the provided {@code digestAlgorithm} (see note below).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param xmlEvidenceRecord {@link XmlEvidenceRecord}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash-tree renewal hash computation
     */
    public XMLEvidenceRecordRenewalDigestBuilder(final XmlEvidenceRecord xmlEvidenceRecord, final DigestAlgorithm digestAlgorithm) {
        super(xmlEvidenceRecord, digestAlgorithm);
    }

    /**
     * Sets a canonicalization method to be used on hash-tree renewal
     * Default: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     * Note: for time-stamp renewal, a canonicalization method defined within a corresponding
     *       ArchiveTimeStampChain is used.
     *
     * @param canonicalizationMethod {@link String}
     * @return this {@link XMLEvidenceRecordRenewalDigestBuilder}
     */
    public XMLEvidenceRecordRenewalDigestBuilder setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        return this;
    }

    @Override
    public XMLEvidenceRecordRenewalDigestBuilder setDetachedContent(List<DSSDocument> detachedContent) {
        return (XMLEvidenceRecordRenewalDigestBuilder) super.setDetachedContent(detachedContent);
    }

    @Override
    public DSSMessageDigest buildTimeStampRenewalDigest() {
        if (digestAlgorithm != null) {
            LOG.info("Provided DigestAlgorithm is ignored on hash computation. " +
                    "The digest algorithm from the last ArchiveTimeStampChain will be used.");
        }
        if (canonicalizationMethod != null) {
            LOG.info("Provided canonicalization method is ignored on hash computation. " +
                    "The canonicalization algorithm from the last ArchiveTimeStampChain will be used.");
        }
        ArchiveTimeStampObject archiveTimeStamp = getLastArchiveTimeStampObject();
        return getArchiveTimeStampSequenceDigestHelper().buildTimeStampRenewalDigest(archiveTimeStamp);
    }

    @Override
    public List<Digest> buildHashTreeRenewalDigestGroup() {
        final List<Digest> result = new ArrayList<>();

        XmlArchiveTimeStampChainObject lastArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) getLastArchiveTimeStampChainObject();
        Digest archiveTimeStampSequenceDigest = getArchiveTimeStampSequenceDigestHelper()
                .buildArchiveTimeStampSequenceDigest(digestAlgorithm, canonicalizationMethod,
                        lastArchiveTimeStampChainObject.getOrder() + 1);
        result.add(archiveTimeStampSequenceDigest);

        if (Utils.isCollectionNotEmpty(detachedContent)) {
            for (DSSDocument detachedDocument : detachedContent) {
                Digest dataObjectDigest = new XMLEvidenceRecordDataObjectDigestBuilder(detachedDocument, digestAlgorithm)
                        .setCanonicalizationMethod(canonicalizationMethod).build();
                result.add(dataObjectDigest);
            }
        } else {
            LOG.warn("No detached content have been provided! Computation of digest for data object has been skipped.");
        }

        return result;
    }

    /**
     * This method returns a helper class containing supporting methods for digest computation in relation
     * to an archive-time-stamp-sequence
     *
     * @return {@link XMLEvidenceRecordRenewalDigestBuilderHelper}
     */
    protected XMLEvidenceRecordRenewalDigestBuilderHelper getArchiveTimeStampSequenceDigestHelper() {
        return new XMLEvidenceRecordRenewalDigestBuilderHelper((XmlEvidenceRecord) evidenceRecord);
    }

}
