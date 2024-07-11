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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;

/**
 * Loads the relevant validator for an ASN.1 Evidence Record document validation
 *
 */
public class ASN1EvidenceRecordAnalyzerFactory implements EvidenceRecordAnalyzerFactory {

    /**
     * Default constructor
     */
    public ASN1EvidenceRecordAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        ASN1EvidenceRecordAnalyzer validator = new ASN1EvidenceRecordAnalyzer();
        return validator.isSupported(document);
    }

    @Override
    public DefaultEvidenceRecordAnalyzer create(DSSDocument document) {
        return new ASN1EvidenceRecordAnalyzer(document);
    }

}
