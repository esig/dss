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
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedAndTimestampedFilesCoveredCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignedAndTimestampedFilesCoveredCheckTest extends AbstractTestCheck {

    @Test
    void asicsOneTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTwoTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFile.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("package.zip");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTwoTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFile.getEntries().add("META-INF/timestamp.tst");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsThreeTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFile.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("package.zip");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp003.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp002.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("package.zip");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp003.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsThreeTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFile.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("package.zip");
        xmlManifestFile.getEntries().add("dataset/test.txt");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp003.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp002.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("package.zip");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp003.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsSigAndTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("META-INF/signature.p7m");
        xmlManifestFile.getEntries().add("package.zip");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsSigAndTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setContentFiles(Collections.singletonList("package.zip"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("META-INF/signature.p7m");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceOneTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceOneTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png", "dataset/alt.txt"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("dataset/alt.txt");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTwoTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("test.txt");
        xmlManifestFileTwo.getEntries().add("image.png");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTwoTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("test.txt");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTwoTstNoTstCoveredValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFileTwo.getEntries().add("test.txt");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceSigAndTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/signature.p7m");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/signature.p7m");
        xmlManifestFileTwo.getEntries().add("test.txt");
        xmlManifestFileTwo.getEntries().add("image.png");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceSigAndTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/signature.p7m");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/signature.p7m");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceThreeTstValidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp001.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("test.txt");
        xmlManifestFileTwo.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileThree = new XmlManifestFile();
        xmlManifestFileThree.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileThree.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFileThree.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileThree.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileThree.getEntries().add("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileThree.getEntries().add("META-INF/timestamp001.tst");
        xmlManifestFileThree.getEntries().add("test.txt");
        xmlManifestFileThree.getEntries().add("image.png");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo, xmlManifestFileThree));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceThreeTstInvalidTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setContentFiles(Arrays.asList("test.txt", "image.png"));

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlManifestFile.setSignatureFilename("META-INF/timestamp.tst");
        xmlManifestFile.getEntries().add("test.txt");
        xmlManifestFile.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileTwo = new XmlManifestFile();
        xmlManifestFileTwo.setFilename("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileTwo.setSignatureFilename("META-INF/timestamp001.tst");
        xmlManifestFileTwo.getEntries().add("META-INF/ASiCManifest.xml");
        xmlManifestFileTwo.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileTwo.getEntries().add("test.txt");
        xmlManifestFileTwo.getEntries().add("image.png");

        XmlManifestFile xmlManifestFileThree = new XmlManifestFile();
        xmlManifestFileThree.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlManifestFileThree.setSignatureFilename("META-INF/timestamp002.tst");
        xmlManifestFileThree.getEntries().add("META-INF/timestamp.tst");
        xmlManifestFileThree.getEntries().add("META-INF/ASiCArchiveManifest001.xml");
        xmlManifestFileThree.getEntries().add("META-INF/timestamp001.tst");
        xmlManifestFileThree.getEntries().add("test.txt");
        xmlManifestFileThree.getEntries().add("image.png");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlManifestFileTwo, xmlManifestFileThree));

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp002.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignedAndTimestampedFilesCoveredCheck stfcc = new SignedAndTimestampedFilesCoveredCheck(
                i18nProvider, result, xmlContainerInfo, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        stfcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
