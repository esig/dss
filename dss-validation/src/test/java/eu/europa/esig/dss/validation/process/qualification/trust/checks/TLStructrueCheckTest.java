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
package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLStructureCheckTest extends AbstractTestCheck {

    @Test
    void validCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(true);
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(false);
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validWithMessageCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(true);
        xmlStructuralValidation.getMessages().add("Valid structure");
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidWithMessageCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlStructuralValidation.setValid(false);
        xmlStructuralValidation.getMessages().add("Error message");
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void nullCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
        xmlTrustedList.setStructuralValidation(xmlStructuralValidation);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noStructureValidationCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLStructureCheck tlsc = new TLStructureCheck(i18nProvider, result, xmlTrustedList, new LevelConstraintWrapper(constraint));
        tlsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
