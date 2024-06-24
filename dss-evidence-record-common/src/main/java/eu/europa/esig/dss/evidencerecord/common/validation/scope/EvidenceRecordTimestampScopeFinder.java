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
package eu.europa.esig.dss.evidencerecord.common.validation.scope;

import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.validation.scope.EvidenceRecordScopeFinder;
import eu.europa.esig.dss.spi.validation.scope.TimestampScopeFinder;

import java.util.Collections;
import java.util.List;

/**
 * Finds timestamped scopes for evidence record time-stamps
 *
 */
public class EvidenceRecordTimestampScopeFinder extends EvidenceRecordScopeFinder implements TimestampScopeFinder {

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public EvidenceRecordTimestampScopeFinder(final EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return evidenceRecord.getEvidenceRecordScopes();
        }
        return Collections.emptyList();
    }

}
