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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.attestation.mdoc.pki.PKICWTStatusListSource;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MdocISONonMdLWithStatusListRevokedTest extends MdocISONonMdLWithStatusListTest {

    @Override
    protected AttestationRevocationSource getAttestationRevocationSource() {
        PKICWTStatusListSource statusListSource = new PKICWTStatusListSource(getCertEntityRepository(), getCertEntity(GOOD_CA));
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) 1);
        statusListSource.setStatusList(bytes);
        return statusListSource;
    }

    @Override
    protected void checkAttestationRevocations(DiagnosticData diagnosticData) {
        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        List<AttestationRevocationWrapper> attestationStatuses = attestation.getAttestationRevocations();
        assertEquals(1, attestationStatuses.size());
        assertEquals(AttestationStatus.INVALID, attestationStatuses.get(0).getStatus());
        assertEquals("application/statuslist+cwt", attestationStatuses.get(0).getType());
    }

}
