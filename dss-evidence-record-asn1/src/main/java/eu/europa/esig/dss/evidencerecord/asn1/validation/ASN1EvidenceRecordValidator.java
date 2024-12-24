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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordValidator;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Class for validation of an ANS.1 Evidence Record (RFC 4998).
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class ASN1EvidenceRecordValidator extends DefaultEvidenceRecordValidator {

    /**
     * Empty constructor
     */
    ASN1EvidenceRecordValidator() {
        super(new ASN1EvidenceRecordAnalyzer());
    }

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(new ASN1EvidenceRecordAnalyzer(document));
    }

    @Override
    public ASN1EvidenceRecordAnalyzer getDocumentAnalyzer() {
        return (ASN1EvidenceRecordAnalyzer) super.getDocumentAnalyzer();
    }

}
