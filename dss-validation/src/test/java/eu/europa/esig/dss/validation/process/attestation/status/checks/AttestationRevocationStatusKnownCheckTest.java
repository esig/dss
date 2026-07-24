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
package eu.europa.esig.dss.validation.process.attestation.status.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationToken;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.attestation.checks.AttestationRevocationStatusKnownCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationRevocationStatusKnownCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationStatus xmlEAARevocationStatus = new XmlEAARevocationStatus();
        xmlEAARevocationStatus.setEAARevocationToken(new XmlEAARevocationToken());
        xmlEAARevocationStatus.setStatus(AttestationStatus.VALID);
        XmlSAV result = new XmlSAV();

        AttestationRevocationStatusKnownCheck eaaskc = new AttestationRevocationStatusKnownCheck(
                i18nProvider, result, new AttestationRevocationWrapper(xmlEAARevocationStatus), new LevelConstraintWrapper(constraint));
        eaaskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationStatus xmlEAARevocationStatus = new XmlEAARevocationStatus();
        xmlEAARevocationStatus.setEAARevocationToken(new XmlEAARevocationToken());
        xmlEAARevocationStatus.setStatus(AttestationStatus.INVALID);
        XmlSAV result = new XmlSAV();

        AttestationRevocationStatusKnownCheck eaaskc = new AttestationRevocationStatusKnownCheck(
                i18nProvider, result, new AttestationRevocationWrapper(xmlEAARevocationStatus), new LevelConstraintWrapper(constraint));
        eaaskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void suspendedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationStatus xmlEAARevocationStatus = new XmlEAARevocationStatus();
        xmlEAARevocationStatus.setEAARevocationToken(new XmlEAARevocationToken());
        xmlEAARevocationStatus.setStatus(AttestationStatus.SUSPENDED);
        XmlSAV result = new XmlSAV();

        AttestationRevocationStatusKnownCheck eaaskc = new AttestationRevocationStatusKnownCheck(
                i18nProvider, result, new AttestationRevocationWrapper(xmlEAARevocationStatus), new LevelConstraintWrapper(constraint));
        eaaskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void unknownTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationStatus xmlEAARevocationStatus = new XmlEAARevocationStatus();
        xmlEAARevocationStatus.setEAARevocationToken(new XmlEAARevocationToken());
        xmlEAARevocationStatus.setStatus(AttestationStatus.UNKNOWN);
        XmlSAV result = new XmlSAV();

        AttestationRevocationStatusKnownCheck eaaskc = new AttestationRevocationStatusKnownCheck(
                i18nProvider, result, new AttestationRevocationWrapper(xmlEAARevocationStatus), new LevelConstraintWrapper(constraint));
        eaaskc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
