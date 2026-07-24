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
import eu.europa.esig.dss.attestation.mdoc.pki.PKICWTIdentifierListSource;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MdocISOMdLIdentifierListRevokedTest extends MdocISOMdLIdentifierListTest {

    @Override
    protected AttestationRevocationSource getEAAStatusSource() {
        PKICWTIdentifierListSource identifierListSource = new PKICWTIdentifierListSource(getCertEntityRepository(), getCertEntity(GOOD_CA));
        identifierListSource.setIdentifiers(Collections.singletonList(new byte[] { 1 }));
        return identifierListSource;
    }

    @Override
    protected void checkEAARevocations(DiagnosticData diagnosticData) {
        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        List<AttestationRevocationWrapper> eaaStatuses = eaa.getAttestationRevocations();
        assertEquals(1, eaaStatuses.size());
        assertEquals(AttestationStatus.INVALID, eaaStatuses.get(0).getStatus());
        assertEquals("application/identifierlist+cwt", eaaStatuses.get(0).getType());
    }

}
