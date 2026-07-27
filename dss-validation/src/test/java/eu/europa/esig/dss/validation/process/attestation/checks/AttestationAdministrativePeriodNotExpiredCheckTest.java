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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationAdministrativePeriodNotExpiredCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        Date now = new Date();
        long nowMil = now.getTime();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(nowMil - 86400000)); // 24 hours ago
        xmlAttestationPayload.setAdministrativeIssuanceDate(notBefore);

        XmlClaim expiration = new XmlClaim();
        expiration.setDateTime(new Date(nowMil + 86400000)); // in 24 hours
        xmlAttestationPayload.setAdministrativeExpirationDate(expiration);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationAdministrativePeriodNotExpiredCheck aapnec = new AttestationAdministrativePeriodNotExpiredCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), now, new LevelConstraintWrapper(constraint));
        aapnec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void expiredTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        Date now = new Date();
        long nowMil = now.getTime();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(nowMil - 172800000)); // 48 hours ago
        xmlAttestationPayload.setAdministrativeIssuanceDate(notBefore);

        XmlClaim expiration = new XmlClaim();
        expiration.setDateTime(new Date(nowMil - 86400000)); // 24 hours ago
        xmlAttestationPayload.setAdministrativeExpirationDate(expiration);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationAdministrativePeriodNotExpiredCheck aapnec = new AttestationAdministrativePeriodNotExpiredCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), now, new LevelConstraintWrapper(constraint));
        aapnec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notYetValidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        Date now = new Date();
        long nowMil = now.getTime();

        XmlClaim notBefore = new XmlClaim();
        notBefore.setDateTime(new Date(nowMil + 86400000)); // 24 hours ago
        xmlAttestationPayload.setAdministrativeIssuanceDate(notBefore);

        XmlClaim expiration = new XmlClaim();
        expiration.setDateTime(new Date(nowMil + 172800000)); // 48 hours after
        xmlAttestationPayload.setAdministrativeExpirationDate(expiration);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationAdministrativePeriodNotExpiredCheck aapnec = new AttestationAdministrativePeriodNotExpiredCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), now, new LevelConstraintWrapper(constraint));
        aapnec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}