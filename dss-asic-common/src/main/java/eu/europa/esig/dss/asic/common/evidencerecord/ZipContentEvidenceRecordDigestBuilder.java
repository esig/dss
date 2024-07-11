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
package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Builds hashes for all documents present within a ZIP archive.
 * Note: for covering an ASiC container with an evidence record, please use {@code ASiCEvidenceRecordDigestBuilder}
 *
 */
public class ZipContentEvidenceRecordDigestBuilder {

    /**
     * List of documents to compute hashes for
     */
    private final List<DSSDocument> documents;

    /**
     * The digest algorithm to be used on hash computation.
     * Default : DigestAlgorithm.SHA256
     */
    protected final DigestAlgorithm digestAlgorithm;

    /**
     * Factory to be used to instantiate a new {@code DataObjectDigestBuilder} for hashes computation
     */
    protected DataObjectDigestBuilderFactory dataObjectDigestBuilderFactory;

    /**
     * Empty constructor
     */
    protected ZipContentEvidenceRecordDigestBuilder() {
        this(DigestAlgorithm.SHA256);
    }

    /**
     * Constructor with defined digest algorithm
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    protected ZipContentEvidenceRecordDigestBuilder(final DigestAlgorithm digestAlgorithm) {
        this.documents = null;
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Creates a ZipContentEvidenceRecordDigestBuilder to build hashes from a {@code DSSDocument},
     * represented by a ZIP container, using a default SHA-256 digest algorithm
     *
     * @param zipContainer {@link DSSDocument} representing a ZIP container, which content will be covered
     *                                         by an Evidence Record
     */
    public ZipContentEvidenceRecordDigestBuilder(final DSSDocument zipContainer) {
        this(zipContainer, DigestAlgorithm.SHA256);
    }

    /**
     * Creates a ZipContentEvidenceRecordDigestBuilder to build hashes with the provided {@code DigestAlgorithm}
     * from a {@code DSSDocument}, represented by a ZIP container
     *
     * @param zipContainer {@link DSSDocument} representing a ZIP container, which content will be covered
     *                                         by an Evidence Record
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on digest computation
     */
    public ZipContentEvidenceRecordDigestBuilder(final DSSDocument zipContainer, final DigestAlgorithm digestAlgorithm) {
        this.documents = extractDocuments(zipContainer);
        this.digestAlgorithm = digestAlgorithm;
    }

    private static List<DSSDocument> extractDocuments(final DSSDocument zipContainer) {
        return ZipUtils.getInstance().extractContainerContent(zipContainer);
    }

    /**
     * Sets a factory to instantiate a new {@code DataObjectDigestBuilder} for hashes computation of
     * the given evidence record type (e.g. XMLERS or ASN.1 ERS)
     *
     * @param dataObjectDigestBuilderFactory {@link DataObjectDigestBuilderFactory}
     * @return this {@link ZipContentEvidenceRecordDigestBuilder}
     */
    public ZipContentEvidenceRecordDigestBuilder setDataObjectDigestBuilderFactory(DataObjectDigestBuilderFactory dataObjectDigestBuilderFactory) {
        this.dataObjectDigestBuilderFactory = dataObjectDigestBuilderFactory;
        return this;
    }

    /**
     * Builds a list of hashes for the content files of the provided ZIP container
     *
     * @return a list of {@link Digest}s
     */
    public List<Digest> buildDigestGroup() {
        assertConfigurationValid();
        return computeDigestForDocuments(documents);
    }

    /**
     * This method verifies whether the configuration of the current builder class is valid
     */
    protected void assertConfigurationValid() {
        Objects.requireNonNull(dataObjectDigestBuilderFactory, "DataObjectDigestBuilderFactory shall be set to continue! " +
                "Please choose the corresponding implementation for your evidence record type (e.g. XMLERS or ASN.1).");
    }

    /**
     * Computes a list of digests for the given list of {@code DSSDocument}s
     *
     * @param documents a list of {@link DSSDocument}s to compute digests for
     * @return a list of {@link Digest}s
     */
    protected List<Digest> computeDigestForDocuments(List<DSSDocument> documents) {
        if (Utils.isCollectionEmpty(documents)) {
            return Collections.emptyList();
        }

        final List<Digest> result = new ArrayList<>();
        for (DSSDocument document : documents) {
            DataObjectDigestBuilder dataObjectDigestBuilder = dataObjectDigestBuilderFactory.create(document, digestAlgorithm);
            Digest digest = dataObjectDigestBuilder.build();
            result.add(digest);
        }
        return result;
    }

}
