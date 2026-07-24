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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.eaa.sd.jwt.pki.PKIJWTStatusListSource;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.eaa.status.AttestationRevocationSource;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SDJWTCompactNoSDWithStatusListRevokedTest extends SDJWTCompactNoSDWithStatusListTest {

    @Override
    protected AttestationRevocationSource getEAAStatusSource() {
        PKIJWTStatusListSource statusListSource = new PKIJWTStatusListSource(getCertEntityRepository(), getCertEntity(GOOD_CA));
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) 1);
        statusListSource.setStatusList(bytes);
        return statusListSource;
    }

    @Override
    protected void checkEAARevocations(DiagnosticData diagnosticData) {
        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        List<AttestationRevocationWrapper> eaaStatuses = eaa.getAttestationRevocations();
        assertEquals(1, eaaStatuses.size());
        assertEquals(AttestationStatus.INVALID, eaaStatuses.get(0).getStatus());
        assertEquals("application/statuslist+jwt", eaaStatuses.get(0).getType());
    }

}
