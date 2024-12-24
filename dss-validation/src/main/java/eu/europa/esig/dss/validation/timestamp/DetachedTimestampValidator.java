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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

/**
 * Detached CMS TimestampToken Validator
 *
 */
public class DetachedTimestampValidator extends SignedDocumentValidator implements TimestampValidator {

    /**
     * Empty constructor
     */
    DetachedTimestampValidator() {
        this(new DetachedTimestampAnalyzer());
    }

    /**
     * Constructor with an analyzer
     *
     * @param detachedTimestampAnalyzer {@link DetachedTimestampAnalyzer}
     */
    protected DetachedTimestampValidator(final DetachedTimestampAnalyzer detachedTimestampAnalyzer) {
        super(detachedTimestampAnalyzer);
    }

    /**
     * The default constructor
     *
     * @param timestampFile {@link DSSDocument} timestamp document to validate
     */
    public DetachedTimestampValidator(final DSSDocument timestampFile) {
        super(new DetachedTimestampAnalyzer(timestampFile));
    }

    /**
     * The default constructor with a type
     *
     * @param timestampFile {@link DSSDocument} timestamp document to validate
     * @param timestampType {@link TimestampType}
     */
    public DetachedTimestampValidator(final DSSDocument timestampFile, TimestampType timestampType) {
        super(new DetachedTimestampAnalyzer(timestampFile, timestampType));
    }

    @Override
    public DetachedTimestampAnalyzer getDocumentAnalyzer() {
        return (DetachedTimestampAnalyzer) super.getDocumentAnalyzer();
    }

    @Override
    public TimestampToken getTimestamp() {
        return getDocumentAnalyzer().getTimestamp();
    }

    /**
     * Sets the data that has been timestamped
     *
     * @param document {@link DSSDocument} timestamped data
     */
    public void setTimestampedData(DSSDocument document) {
        getDocumentAnalyzer().setTimestampedData(document);
    }

    @Override
    public DSSDocument getTimestampedData() {
        return getDocumentAnalyzer().getTimestampedData();
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(String signatureId) {
        throw new UnsupportedOperationException("getOriginalDocuments(signatureId) is " +
                "not supported for DetachedTimestampValidator!");
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature) is " +
                "not supported for DetachedTimestampValidator!");
    }

}