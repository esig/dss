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

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;

import java.util.List;
import java.util.Objects;

/**
 * This class is used to build hashes for data objects within an ASiC container for
 * potential evidence-record incorporation
 *
 */
public class ASiCEvidenceRecordDigestBuilder extends ZipContentEvidenceRecordDigestBuilder {

    /**
     * Content of an ASiC container
     */
    private final ASiCContent asicContent;

    /**
     * This class is used to filter the documents to compute hashes for
     */
    private ASiCContentDocumentFilter asicContentDocumentFilter;

    /**
     * Creates a ASiCEvidenceRecordDigestBuilder to build hashes from a {@code DSSDocument},
     * represented by an ASiC container, using a default SHA-256 digest algorithm
     *
     * @param asicContainer {@link ASiCContent} representing a content of an ASiC archive
     * @throws IllegalInputException if the provided document is not of a supported ASiC container type
     */
    public ASiCEvidenceRecordDigestBuilder(final DSSDocument asicContainer) throws IllegalInputException {
        this(asicContainer, DigestAlgorithm.SHA256);
    }

    /**
     * Creates a ASiCEvidenceRecordDigestBuilder to build hashes with the provided {@code DigestAlgorithm}
     * from a {@code DSSDocument}, represented by an ASiC container
     *
     * @param asicContainer {@link ASiCContent} representing a content of an ASiC archive
     * @throws IllegalInputException if the provided document is not of a supported ASiC container type
     */
    public ASiCEvidenceRecordDigestBuilder(final DSSDocument asicContainer, final DigestAlgorithm digestAlgorithm) throws IllegalInputException {
        this(toASiCContent(asicContainer), digestAlgorithm);
    }

    private static ASiCContent toASiCContent(final DSSDocument asicContainer) {
        try {
            ASiCContainerExtractor asicContainerExtractor = DefaultASiCContainerExtractor.fromDocument(asicContainer);
            return asicContainerExtractor.extract();
        } catch (Exception e) {
            throw new IllegalInputException(String.format("Unsupported ASiC or document type! Returned error : %s", e.getMessage()), e);
        }
    }

    /**
     * Creates a ASiCEvidenceRecordDigestBuilder to build hashes from {@code ASiCContent},
     * using a default SHA-256 digest algorithm
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC archive
     */
    public ASiCEvidenceRecordDigestBuilder(final ASiCContent asicContent) {
        this(asicContent, DigestAlgorithm.SHA256);
    }

    /**
     * Creates a ASiCEvidenceRecordDigestBuilder to build hashes with the provided {@code DigestAlgorithm}
     * from {@code ASiCContent}
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC archive
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hashes computation
     */
    public ASiCEvidenceRecordDigestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm) {
        super(digestAlgorithm);
        this.asicContent = asicContent;
    }

    /**
     * Sets a factory to instantiate a new {@code DataObjectDigestBuilder} for hashes computation of
     * the given evidence record type (e.g. XMLERS or ASN.1 ERS)
     *
     * @param dataObjectDigestBuilderFactory {@link DataObjectDigestBuilderFactory}
     * @return this {@link ASiCEvidenceRecordDigestBuilder}
     */
    public ASiCEvidenceRecordDigestBuilder setDataObjectDigestBuilderFactory(DataObjectDigestBuilderFactory dataObjectDigestBuilderFactory) {
        super.setDataObjectDigestBuilderFactory(dataObjectDigestBuilderFactory);
        return this;
    }

    /**
     * Sets an {@code ASiCContentDocumentFilter} used to filter the documents to compute hashes for
     *
     * @param asicContentDocumentFilter {@link ASiCContentDocumentFilter}
     * @return this {@link ASiCEvidenceRecordDigestBuilder}
     */
    public ASiCEvidenceRecordDigestBuilder setAsicContentDocumentFilter(ASiCContentDocumentFilter asicContentDocumentFilter) {
        this.asicContentDocumentFilter = asicContentDocumentFilter;
        return this;
    }

    @Override
    public List<Digest> buildDigestGroup() {
        assertConfigurationValid();

        final List<DSSDocument> documents = getDocumentListToComputeDigest();
        return computeDigestForDocuments(documents);
    }

    @Override
    protected void assertConfigurationValid() {
        super.assertConfigurationValid();
        Objects.requireNonNull(asicContentDocumentFilter, "ASiCContentDocumentFilter shall be set to continue! " +
                "Use ASiCContentDocumentFilterFactory to facilitate configuration.");
    }

    /**
     * This method executes an {@code AsicContentDocumentFilter} and returns a list of documents to compute hashes for
     *
     * @return a list of {@link DSSDocument}s
     */
    protected List<DSSDocument> getDocumentListToComputeDigest() {
        return asicContentDocumentFilter.filter(asicContent);
    }

}
