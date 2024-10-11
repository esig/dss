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
import eu.europa.esig.dss.evidencerecord.asn1.validation.timestamp.ASN1EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.tsp.EvidenceRecord;

import java.util.Objects;

/**
 * ASN.1 Evidence Record implementations (RFC 4998)
 *
 */
public class ASN1EvidenceRecord extends DefaultEvidenceRecord {

    /** The current EvidenceRecord object */
    private final EvidenceRecord evidenceRecord;


    /**
     * Constructor to instantiate an ASN.1 Evidence Record from a {@code DSSDocument}
     *
     * @param document {@link DSSDocument} containing the evidence record
     */
    public ASN1EvidenceRecord(DSSDocument document) {
        Objects.requireNonNull(document, "Document cannot be null!");
        this.evidenceRecord = toASN1Document(document);
    }

    private org.bouncycastle.asn1.tsp.EvidenceRecord toASN1Document(DSSDocument document) {
        try {
            return org.bouncycastle.asn1.tsp.EvidenceRecord.getInstance(DSSUtils.toByteArray(document));
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An ASN.1 file is expected : %s", e.getMessage()), e);
        }
    }

    /**
     * Default constructor to instantiate an ASN.1 Evidence Record
     *
     * @param evidenceRecord {@link EvidenceRecord} representing the evidence record document
     */
    public ASN1EvidenceRecord(EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }
    
    /**
     * Gets the BouncyCastle EvidenceRecord object
     *
     * @return {@link EvidenceRecord}
     */
    public EvidenceRecord getEvidenceRecord() {
        return evidenceRecord;
    }

    @Override
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

    @Override
    protected EvidenceRecordParser buildEvidenceRecordParser() {
        return new ASN1EvidenceRecordParser(evidenceRecord);
    }

    @Override
    protected EvidenceRecordTimeStampSequenceVerifier buildCryptographicEvidenceRecordVerifier() {
        return new ASN1EvidenceRecordTimeStampSequenceVerifier(this);
    }

    @Override
    protected EvidenceRecordTimestampSource<?> buildTimestampSource() {
        return new ASN1EvidenceRecordTimestampSource(this);
    }

    @Override
    public byte[] getEncoded() {
        return DSSASN1Utils.getDEREncoded(evidenceRecord);
    }

}
