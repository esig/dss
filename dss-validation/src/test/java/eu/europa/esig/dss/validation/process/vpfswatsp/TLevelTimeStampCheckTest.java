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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TLevelTimeStampCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TLevelTimeStampCheckTest extends AbstractTestCheck {

    private static final String TST_ID = "TST-1";

    @Test
    void valid() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.PASSED);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.INDETERMINATE);
        tstBasicConclusion.setSubIndication(SubIndication.OUT_OF_BOUNDS_NO_POE);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void multipleTsts() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.PASSED);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        timestamp = new XmlTimestamp();
        timestamp.setId("TST-2");
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId("TST-2");

        bbbs.put("TST-2", tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestampTwo = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestampTwo.setId("TST-2");

        xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.INDETERMINATE);
        tstBasicConclusion.setSubIndication(SubIndication.OUT_OF_BOUNDS_NO_POE);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestampTwo.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Arrays.asList(xmlTimestamp, xmlTimestampTwo), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void multipleTstsInvalid() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.FAILED);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        timestamp = new XmlTimestamp();
        timestamp.setId("TST-2");
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId("TST-2");

        bbbs.put("TST-2", tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestampTwo = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestampTwo.setId("TST-2");

        xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.INDETERMINATE);
        tstBasicConclusion.setSubIndication(SubIndication.OUT_OF_BOUNDS_NO_POE);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestampTwo.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Arrays.asList(xmlTimestamp, xmlTimestampTwo), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void psvTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        XmlPSV xmlPSV = new XmlPSV();
        XmlConclusion psvConclusion = new XmlConclusion();
        psvConclusion.setIndication(Indication.PASSED);
        xmlPSV.setConclusion(psvConclusion);
        tstBBB.setPSV(xmlPSV);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.INDETERMINATE);
        tstBasicConclusion.setSubIndication(SubIndication.OUT_OF_BOUNDS_NO_POE);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void psvWithNotAllowedIndicationTest() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        XmlPSV xmlPSV = new XmlPSV();
        XmlConclusion psvConclusion = new XmlConclusion();
        psvConclusion.setIndication(Indication.PASSED);
        xmlPSV.setConclusion(psvConclusion);
        tstBBB.setPSV(xmlPSV);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.INDETERMINATE);
        tstBasicConclusion.setSubIndication(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidType() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.PASSED);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void docTstType() {
        XmlSignature xmlSignature = new XmlSignature();

        XmlTimestamp timestamp = new XmlTimestamp();
        timestamp.setId(TST_ID);
        timestamp.setType(TimestampType.DOCUMENT_TIMESTAMP);
        timestamp.setArchiveTimestampType(ArchiveTimestampType.PAdES);

        XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
        foundTimestamp.setTimestamp(timestamp);
        xmlSignature.getFoundTimestamps().add(foundTimestamp);

        Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();

        XmlBasicBuildingBlocks tstBBB = new XmlBasicBuildingBlocks();
        tstBBB.setId(TST_ID);

        bbbs.put(TST_ID, tstBBB);

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        xmlTimestamp.setId(TST_ID);

        XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp = new XmlValidationProcessBasicTimestamp();
        XmlConclusion tstBasicConclusion = new XmlConclusion();
        tstBasicConclusion.setIndication(Indication.PASSED);
        xmlValidationProcessBasicTimestamp.setConclusion(tstBasicConclusion);
        xmlTimestamp.setValidationProcessBasicTimestamp(xmlValidationProcessBasicTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessArchivalData result = new XmlValidationProcessArchivalData();
        TLevelTimeStampCheck<XmlValidationProcessArchivalData> tltsc = new TLevelTimeStampCheck<>(i18nProvider, result, new SignatureWrapper(xmlSignature),
                bbbs, Collections.singleton(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tltsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
