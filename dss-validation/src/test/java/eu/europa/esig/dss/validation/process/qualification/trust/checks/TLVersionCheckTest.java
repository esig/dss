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
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLVersionCheckTest extends AbstractTestCheck {

    private static final Date PRE_GRACE_PERIOD_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

    private static final Date POST_GRACE_PERIOD_DATE = DatatypeConverter.parseDateTime("2017-07-01T00:00:00.000Z").getTime();

    @Test
    void validCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("5");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(5);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, POST_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void validTLv6Check() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("5");
        constraint.getId().add("6");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(6);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, POST_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("6");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(5);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, POST_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validPreGracePeriodCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("5");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(5);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, PRE_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidPreGracePeriodCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("6");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(5);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, PRE_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void acceptAllCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("*");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();
        xmlTrustedList.setVersion(5);

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, POST_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void nullCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("5");

        XmlTrustedList xmlTrustedList = new XmlTrustedList();

        XmlTLAnalysis result = new XmlTLAnalysis();
        TLVersionCheck tlvc = new TLVersionCheck(i18nProvider, result, xmlTrustedList, POST_GRACE_PERIOD_DATE, new MultiValuesConstraintWrapper(constraint));
        tlvc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
