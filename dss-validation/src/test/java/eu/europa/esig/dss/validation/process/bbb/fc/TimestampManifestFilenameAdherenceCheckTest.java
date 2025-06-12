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
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.TimestampManifestFilenameAdherenceCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TimestampManifestFilenameAdherenceCheckTest extends AbstractTestCheck {

    @Test
    void asicsTstManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTstManifestDiffNameValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/manifest001.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstManifestDiffNameValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest001.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstManifestCoverageInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlSecondTimestamp = new XmlTimestamp();
        xmlSecondTimestamp.setTimestampFilename("META-INF/timestamp001.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSecondTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest001.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlSecondTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstManifestInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsArcTstManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsArcTstManifestDiffNameValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml"); // TODO : 5) c) Other application specific information. ?
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceArcTstManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceArcTstManifestDiffNameNotLastValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest001.xml");

        XmlTimestamp xmlLastArcTimestamp = new XmlTimestamp();
        xmlLastArcTimestamp.setTimestampFilename("META-INF/arc_timestamp_002.tst");

        XmlManifestFile xmlLastManifestFile = new XmlManifestFile();
        xmlLastManifestFile.setSignatureFilename(xmlLastArcTimestamp.getTimestampFilename());
        xmlLastManifestFile.getEntries().add(xmlArcTimestamp.getTimestampFilename());
        xmlLastManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");

        xmlContainerInfo.setManifestFiles(Arrays.asList(xmlManifestFile, xmlLastManifestFile));
        xmlDiagnosticData.setUsedTimestamps(Arrays.asList(xmlTimestamp, xmlArcTimestamp, xmlLastArcTimestamp));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceArcTstManifestDiffNameLastInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest001.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        xmlDiagnosticData.setUsedTimestamps(Arrays.asList(xmlTimestamp, xmlArcTimestamp));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceArcTstManifestDiffNameInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.getEntries().add(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceArcTstManifestCoverageInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlArcTimestamp = new XmlTimestamp();
        xmlArcTimestamp.setTimestampFilename("META-INF/arc_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlArcTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampManifestFilenameAdherenceCheck tmfac = new TimestampManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlArcTimestamp), new LevelConstraintWrapper(constraint));
        tmfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
