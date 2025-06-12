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
package eu.europa.esig.dss.cades;

import java.io.Serializable;
import java.util.Comparator;

/**
 * The class is used to compare production time of {@code org.bouncycastle.asn1.tsp.EvidenceRecord}s
 * Class checks the generation time of evidence records
 * <p>
 * The method compare() returns
 *     -1 if the {@code evidenceRecordOne} was created before {@code evidenceRecordTwo}
 *     0 if EvidenceRecord's were created at the same time
 *     1 if the {@code evidenceRecordOne} was created after {@code evidenceRecordTwo}
 *
 */
public class EvidenceRecordProductionComparator implements Comparator<org.bouncycastle.asn1.tsp.EvidenceRecord>, Serializable {

    private static final long serialVersionUID = 7426569998197138099L;

    /**
     * Default constructor
     */
    public EvidenceRecordProductionComparator() {
        // empty
    }

    @Override
    public int compare(org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordOne, org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordTwo) {
        return compareByGenerationTime(evidenceRecordOne, evidenceRecordTwo);
    }

    private int compareByGenerationTime(org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordOne, org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordTwo) {
        return CAdESUtils.getEvidenceRecordGenerationTime(evidenceRecordOne).compareTo(CAdESUtils.getEvidenceRecordGenerationTime(evidenceRecordTwo));
    }

}
