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
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationTypeCheckTest extends AbstractTestCheck {

    @Test
    void sdjwtValidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("urn:eudi:pid:1");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdjwtValidAllValuesTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocValidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("urn:eudi:pid:1");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        xmlEAA.setDocumentType("urn:eudi:pid:1");

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocValidAllValuesTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        xmlEAA.setDocumentType("urn:eudi:pid:1");

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sdjwtInvalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("urn:eudi:pid:2");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);
        XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlEAAPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlEAA.setEAAPayload(xmlEAAPayload);

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocInvalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("urn:eudi:pid:2");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);
        xmlEAA.setDocumentType("urn:eudi:pid:1");

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void sdjwtNotPresentTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.SD_JWT_VC);

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void mdocNotPresentTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAA xmlEAA = new XmlEAA();
        xmlEAA.setEAAType(AttestationFormat.ISO_IEC_MDOC);

        XmlSAV result = new XmlSAV();

        AttestationTypeCheck typePresentCheck = new AttestationTypeCheck(
                i18nProvider, result, new AttestationWrapper(xmlEAA), new MultiValuesConstraintWrapper(constraint));
        typePresentCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }
}
