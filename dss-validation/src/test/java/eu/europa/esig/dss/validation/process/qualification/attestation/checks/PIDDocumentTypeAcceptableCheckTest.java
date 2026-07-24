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
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.enumerations.AttestationFormat;
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

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidDeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1:de");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidNotEuTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:zzdi:pid:1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void sdJwtPidDocTypeTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        xmlEAA.setDocumentType("urn:eudi:pid:1");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        xmlEAA.setDocumentType("eu.europa.ec.eudi.pid.1");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidWrongTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        xmlEAA.setDocumentType("eu.europa.ec.eudi.pid.1.de");

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocPidMetadataClaimTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("eu.europa.ec.eudi.pid.1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlValidationPIDQualificationProcess result = new XmlValidationPIDQualificationProcess();

        PIDDocumentTypeAcceptableCheck tlscbpsc = new PIDDocumentTypeAcceptableCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new LevelConstraintWrapper(constraint));
        tlscbpsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
