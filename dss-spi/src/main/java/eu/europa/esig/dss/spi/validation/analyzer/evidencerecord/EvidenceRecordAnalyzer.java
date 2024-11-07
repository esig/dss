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
package eu.europa.esig.dss.spi.validation.analyzer.evidencerecord;

import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

/**
 * Interface to perform validation of an evidence record document
 *
 */
public interface EvidenceRecordAnalyzer extends DocumentAnalyzer {

    /**
     * Returns a single EvidenceRecord to be validated
     *
     * @return {@link EvidenceRecord}
     */
    EvidenceRecord getEvidenceRecord();

    /**
     * This method returns a type of the evidence record supported by the current validator
     *
     * @return {@link EvidenceRecordTypeEnum}
     */
    EvidenceRecordTypeEnum getEvidenceRecordType();

    /**
     * Sets the origin of the extracted evidence record
     * <p>
     * Default : EvidenceRecordOrigin.EXTERNAL
     *
     * @param origin {@link EvidenceRecordOrigin}
     */
    void setEvidenceRecordOrigin(EvidenceRecordOrigin origin);

}
