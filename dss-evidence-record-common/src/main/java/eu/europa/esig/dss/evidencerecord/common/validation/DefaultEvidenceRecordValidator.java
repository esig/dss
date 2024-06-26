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
package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;

import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class is used to perform a validation of an evidence record document
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public abstract class DefaultEvidenceRecordValidator extends SignedDocumentValidator implements EvidenceRecordValidator {

    /**
     * Empty constructor
     */
    protected DefaultEvidenceRecordValidator(final DefaultEvidenceRecordAnalyzer evidenceRecordAnalyzer) {
        super(evidenceRecordAnalyzer);
    }

    @Override
    public DefaultEvidenceRecordAnalyzer getDocumentAnalyzer() {
        return (DefaultEvidenceRecordAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * This method guesses the document format and returns an appropriate
     * evidence record validator.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link DefaultEvidenceRecordValidator} in terms of the document type
     */
    public static DefaultEvidenceRecordValidator fromDocument(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "DSSDocument is null");
        ServiceLoader<EvidenceRecordValidatorFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordValidatorFactory.class);
        for (EvidenceRecordValidatorFactory factory : serviceLoaders) {
            if (factory.isSupported(dssDocument)) {
                return factory.create(dssDocument);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    @Override
    public EvidenceRecord getEvidenceRecord() {
        return getDocumentAnalyzer().getEvidenceRecord();
    }

    @Override
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return getDocumentAnalyzer().getEvidenceRecordType();
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature) is " +
                "not supported for EvidenceRecordValidator!");
    }

}