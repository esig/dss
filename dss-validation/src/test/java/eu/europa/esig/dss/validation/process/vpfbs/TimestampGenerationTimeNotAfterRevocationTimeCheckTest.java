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
package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterRevocationTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TimestampGenerationTimeNotAfterRevocationTimeCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        Date revocationTime = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(revocationTime);
        calendar.add(Calendar.MONTH, -1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterRevocationTimeCheck tgtnartc = new TimestampGenerationTimeNotAfterRevocationTimeCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), revocationTime, constraint);
        tgtnartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        Date revocationTime = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(revocationTime);
        calendar.add(Calendar.MONTH, 1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCertificateExpirationCheck tgtnartc = new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), revocationTime, constraint);
        tgtnartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void sameTimeTest() {
        Date datetime = new Date();

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(datetime);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCertificateExpirationCheck tgtnartc = new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), datetime, constraint);
        tgtnartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void contentTstMillisecondAfterTest() {
        Date revocationTime = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(revocationTime);
        calendar.add(Calendar.MILLISECOND, 1);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(calendar.getTime());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessBasicSignature result = new XmlValidationProcessBasicSignature();
        TimestampGenerationTimeNotAfterCertificateExpirationCheck tgtnartc = new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(
                i18nProvider, result, new TimestampWrapper(xmlTimestamp), revocationTime, constraint);
        tgtnartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
