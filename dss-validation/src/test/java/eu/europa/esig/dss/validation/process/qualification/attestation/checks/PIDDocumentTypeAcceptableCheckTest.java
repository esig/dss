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
package eu.europa.esig.dss.validation.process.qualification.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationPIDQualificationProcess;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks.PIDDocumentTypeAcceptableCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PIDDocumentTypeAcceptableCheckTest extends AbstractTestCheck {

    @Test
    void sdJwtPidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidDeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1:de");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidNotEuTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:zzdi:pid:1");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidDocTypeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        xmlAttestation.setDocumentType("urn:eudi:pid:1");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("eu.europa.ec.eudi.pid.1");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidWrongTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        xmlAttestation.setDocumentType("eu.europa.ec.eudi.pid.1.de");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidMetadataClaimTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.ISO_IEC_MDOC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("eu.europa.ec.eudi.pid.1");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
