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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * POE provided by an evidence record
 *
 */
public class EvidenceRecordPOE extends POE {

    /** The evidence record */
    private final EvidenceRecordWrapper evidenceRecord;

    /**
     * The constructor to instantiate POE by an evidence record
     *
     * @param evidenceRecord {@link EvidenceRecordWrapper}
     */
    public EvidenceRecordPOE(EvidenceRecordWrapper evidenceRecord) {
        super(getPOETime(evidenceRecord));
        this.evidenceRecord = evidenceRecord;
    }

    private static Date getPOETime(EvidenceRecordWrapper evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "The evidenceRecord must be defined!");
        Objects.requireNonNull(evidenceRecord.getFirstTimestamp(), "EvidenceRecord shall have at leats one time-stamp!");
        return evidenceRecord.getFirstTimestamp().getProductionTime();
    }

    @Override
    public String getPOEProviderId() {
        return evidenceRecord.getId();
    }

    @Override
    public List<XmlTimestampedObject> getPOEObjects() {
        return evidenceRecord.getCoveredObjects();
    }

    @Override
    public boolean isTokenProvided() {
        return true;
    }

}
