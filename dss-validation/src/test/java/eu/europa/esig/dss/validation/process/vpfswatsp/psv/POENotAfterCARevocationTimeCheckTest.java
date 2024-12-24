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
package eu.europa.esig.dss.validation.process.vpfswatsp.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POENotAfterCARevocationTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class POENotAfterCARevocationTimeCheckTest extends AbstractTestCheck {

    private static final String REVOC_ONE_ID = "R-1";
    private static final String REVOC_TWO_ID = "R-2";

    @Test
    void validCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        XmlTimestampedObject xmlTimestampedObjectTwo = new XmlTimestampedObject();
        xmlTimestampedObjectTwo.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectTwo.setToken(xmlRevocationTwo);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectTwo);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void onlyOneRevocPOECheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void anotherRevocPoeCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() - 86400000)); // 24 hours ago

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTstTimeCheck() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Date caRevocationTime = new Date();

        XmlRevocation xmlRevocationOne = new XmlRevocation();
        xmlRevocationOne.setId(REVOC_ONE_ID);

        XmlRevocation xmlRevocationTwo = new XmlRevocation();
        xmlRevocationTwo.setId(REVOC_TWO_ID);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setProductionTime(new Date(caRevocationTime.getTime() + 86400000)); // 24 hours after

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
        xmlDigestMatcher.setDataFound(true);
        xmlDigestMatcher.setDataIntact(true);
        xmlTimestamp.getDigestMatchers().add(xmlDigestMatcher);

        XmlTimestampedObject xmlTimestampedObjectOne = new XmlTimestampedObject();
        xmlTimestampedObjectOne.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectOne.setToken(xmlRevocationOne);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectOne);

        XmlTimestampedObject xmlTimestampedObjectTwo = new XmlTimestampedObject();
        xmlTimestampedObjectTwo.setCategory(TimestampedObjectType.REVOCATION);
        xmlTimestampedObjectTwo.setToken(xmlRevocationTwo);
        xmlTimestamp.getTimestampedObjects().add(xmlTimestampedObjectTwo);

        POEExtraction poeExtraction = new POEExtraction();
        poeExtraction.extractPOE(new TimestampWrapper(xmlTimestamp));

        XmlPSV result = new XmlPSV();
        POENotAfterCARevocationTimeCheck pnacartc = new POENotAfterCARevocationTimeCheck<>(i18nProvider, result,
                Arrays.asList(new RevocationWrapper(xmlRevocationOne), new RevocationWrapper(xmlRevocationTwo)),
                caRevocationTime, poeExtraction, constraint);
        pnacartc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
