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
package eu.europa.esig.dss.validation.process.vpftspwatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks.EvidenceRecordSignedFilesCoveredCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EvidenceRecordSignedFilesCoveredCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        XmlDigestMatcher xmlDigestMatcherOne = new XmlDigestMatcher();
        xmlDigestMatcherOne.setDocumentName("doc1.xml");

        XmlDigestMatcher xmlDigestMatcherTwo = new XmlDigestMatcher();
        xmlDigestMatcherTwo.setDocumentName("doc2.xml");

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setToken(xmlSignature);
        xmlTimestampedObject.setCategory(TimestampedObjectType.SIGNATURE);
        xmlEvidenceRecord.getTimestampedObjects().add(xmlTimestampedObject);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessEvidenceRecord result = new XmlValidationProcessEvidenceRecord();
        EvidenceRecordSignedFilesCoveredCheck ersfcc = new EvidenceRecordSignedFilesCoveredCheck(
                i18nProvider, result, new EvidenceRecordWrapper(xmlEvidenceRecord), constraint);
        ersfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void missingScopeTest() {
        XmlDigestMatcher xmlDigestMatcherOne = new XmlDigestMatcher();
        xmlDigestMatcherOne.setDocumentName("doc1.xml");

        XmlDigestMatcher xmlDigestMatcherTwo = new XmlDigestMatcher();
        xmlDigestMatcherTwo.setDocumentName("doc2.xml");

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherOne);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setToken(xmlSignature);
        xmlTimestampedObject.setCategory(TimestampedObjectType.SIGNATURE);
        xmlEvidenceRecord.getTimestampedObjects().add(xmlTimestampedObject);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessEvidenceRecord result = new XmlValidationProcessEvidenceRecord();
        EvidenceRecordSignedFilesCoveredCheck ersfcc = new EvidenceRecordSignedFilesCoveredCheck(
                i18nProvider, result, new EvidenceRecordWrapper(xmlEvidenceRecord), constraint);
        ersfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void diffScopeTest() {
        XmlDigestMatcher xmlDigestMatcherOne = new XmlDigestMatcher();
        xmlDigestMatcherOne.setDocumentName("doc1.xml");

        XmlDigestMatcher xmlDigestMatcherTwo = new XmlDigestMatcher();
        xmlDigestMatcherTwo.setDocumentName("doc2.xml");

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlDigestMatcher xmlDigestMatcherThree = new XmlDigestMatcher();
        xmlDigestMatcherThree.setDocumentName("doc3.xml");

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherThree);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setToken(xmlSignature);
        xmlTimestampedObject.setCategory(TimestampedObjectType.SIGNATURE);
        xmlEvidenceRecord.getTimestampedObjects().add(xmlTimestampedObject);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessEvidenceRecord result = new XmlValidationProcessEvidenceRecord();
        EvidenceRecordSignedFilesCoveredCheck ersfcc = new EvidenceRecordSignedFilesCoveredCheck(
                i18nProvider, result, new EvidenceRecordWrapper(xmlEvidenceRecord), constraint);
        ersfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void additionalScopeTest() {
        XmlDigestMatcher xmlDigestMatcherOne = new XmlDigestMatcher();
        xmlDigestMatcherOne.setDocumentName("doc1.xml");

        XmlDigestMatcher xmlDigestMatcherTwo = new XmlDigestMatcher();
        xmlDigestMatcherTwo.setDocumentName("doc2.xml");

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherOne);

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setToken(xmlSignature);
        xmlTimestampedObject.setCategory(TimestampedObjectType.SIGNATURE);
        xmlEvidenceRecord.getTimestampedObjects().add(xmlTimestampedObject);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessEvidenceRecord result = new XmlValidationProcessEvidenceRecord();
        EvidenceRecordSignedFilesCoveredCheck ersfcc = new EvidenceRecordSignedFilesCoveredCheck(
                i18nProvider, result, new EvidenceRecordWrapper(xmlEvidenceRecord), constraint);
        ersfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void nullDocNameTest() {
        XmlDigestMatcher xmlDigestMatcherOne = new XmlDigestMatcher();
        xmlDigestMatcherOne.setDocumentName("doc1.xml");

        XmlDigestMatcher xmlDigestMatcherTwo = new XmlDigestMatcher();
        xmlDigestMatcherTwo.setDocumentName(null);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlSignature.getDigestMatchers().add(xmlDigestMatcherTwo);

        XmlDigestMatcher xmlDigestMatcherThree = new XmlDigestMatcher();
        xmlDigestMatcherThree.setDocumentName("doc3.xml");

        XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherOne);
        xmlEvidenceRecord.getDigestMatchers().add(xmlDigestMatcherThree);

        XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
        xmlTimestampedObject.setToken(xmlSignature);
        xmlTimestampedObject.setCategory(TimestampedObjectType.SIGNATURE);
        xmlEvidenceRecord.getTimestampedObjects().add(xmlTimestampedObject);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessEvidenceRecord result = new XmlValidationProcessEvidenceRecord();
        EvidenceRecordSignedFilesCoveredCheck ersfcc = new EvidenceRecordSignedFilesCoveredCheck(
                i18nProvider, result, new EvidenceRecordWrapper(xmlEvidenceRecord), constraint);
        ersfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
