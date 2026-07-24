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
package eu.europa.esig.dss.validation.process.eaa.status.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAASubject;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.eaa.status.AttestationRevocationSubjectCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationRevocationSubjectCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("https://dss.nowina.lu/pki-factory/eaa/status");
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationToken xmlEAARevocationToken = new XmlEAARevocationToken();
        XmlEAASubject xmlEAASubject = new XmlEAASubject();
        xmlEAASubject.setValue("https://dss.nowina.lu/pki-factory/eaa/status");
        xmlEAARevocationToken.setSubject(xmlEAASubject);
        XmlSAV result = new XmlSAV();

        AttestationRevocationSubjectCheck eaassc = new AttestationRevocationSubjectCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlEAARevocationToken), new MultiValuesConstraintWrapper(constraint));
        eaassc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("https://dss.nowina.lu/pki-factory/eaa/status");
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationToken xmlEAARevocationToken = new XmlEAARevocationToken();
        XmlEAASubject xmlEAASubject = new XmlEAASubject();
        xmlEAASubject.setValue("https://dss.nowina.lu/pki-factory/neaa/status");
        xmlEAARevocationToken.setSubject(xmlEAASubject);
        XmlSAV result = new XmlSAV();

        AttestationRevocationSubjectCheck eaassc = new AttestationRevocationSubjectCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlEAARevocationToken), new MultiValuesConstraintWrapper(constraint));
        eaassc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void allTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationToken xmlEAARevocationToken = new XmlEAARevocationToken();
        XmlEAASubject xmlEAASubject = new XmlEAASubject();
        xmlEAASubject.setValue("https://dss.nowina.lu/pki-factory/eaa/status");
        xmlEAARevocationToken.setSubject(xmlEAASubject);
        XmlSAV result = new XmlSAV();

        AttestationRevocationSubjectCheck eaassc = new AttestationRevocationSubjectCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlEAARevocationToken), new MultiValuesConstraintWrapper(constraint));
        eaassc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notPresentTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlEAARevocationToken xmlEAARevocationToken = new XmlEAARevocationToken();
        XmlSAV result = new XmlSAV();

        AttestationRevocationSubjectCheck eaassc = new AttestationRevocationSubjectCheck(
                i18nProvider, result, new AttestationRevocationTokenWrapper(xmlEAARevocationToken), new MultiValuesConstraintWrapper(constraint));
        eaassc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
