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

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

/**
 * Class for validation of an ASN.1 Evidence Record (RFC 4998)
 *
 */
public class ASN1EvidenceRecordAnalyzer extends DefaultEvidenceRecordAnalyzer {

    /** The root object of the document to validate */
    private org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordObject;

    /**
     * The default constructor for ASN1EvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordAnalyzer(final DSSDocument document) {
        super(document);
        this.evidenceRecordObject = toASN1Document(document);
    }

	/**
     * Empty constructor
     */
    ASN1EvidenceRecordAnalyzer() {
        // empty
    }
    
    private org.bouncycastle.asn1.tsp.EvidenceRecord toASN1Document(DSSDocument document) {
        try {
            return org.bouncycastle.asn1.tsp.EvidenceRecord.getInstance(DSSUtils.toByteArray(document));
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An ASN.1 file is expected : %s", e.getMessage()), e);
        }
	}

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        byte firstByte = DSSUtils.readFirstByte(dssDocument);
        return DSSASN1Utils.isASN1SequenceTag(firstByte) && canBuildEvidenceRecord(dssDocument);
    }

    private boolean canBuildEvidenceRecord(DSSDocument dssDocument) {
        try {
            toASN1Document(dssDocument);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected EvidenceRecord buildEvidenceRecord() {
        final ASN1EvidenceRecord evidenceRecord = new ASN1EvidenceRecord(this.evidenceRecordObject);
        evidenceRecord.setFilename(document.getName());
        evidenceRecord.setOrigin(evidenceRecordOrigin);
        evidenceRecord.setManifestFile(manifestFile);
        evidenceRecord.setDetachedContents(detachedContents);
        return evidenceRecord;
    }

    @Override
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

}
