/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.BestSignatureTimeBeforeSuspensionTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class BestSignatureTimeBeforeSuspensionTimeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil + 43200000)); // 12 hours after

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        BestSignatureTimeBeforeSuspensionTimeCheck bstbstc = new BestSignatureTimeBeforeSuspensionTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint);
        bstbstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNull(conclusion);

    }

    @Test
    void invalidTest() {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil - 43200000)); // 12 hours before

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        BestSignatureTimeBeforeSuspensionTimeCheck bstbstc = new BestSignatureTimeBeforeSuspensionTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint);
        bstbstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.TRY_LATER, conclusion.getSubIndication());

    }

    @Test
    void sameTimeTest() {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil)); // same time

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        BestSignatureTimeBeforeSuspensionTimeCheck bstbstc = new BestSignatureTimeBeforeSuspensionTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint);
        bstbstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.TRY_LATER, conclusion.getSubIndication());

    }

}
