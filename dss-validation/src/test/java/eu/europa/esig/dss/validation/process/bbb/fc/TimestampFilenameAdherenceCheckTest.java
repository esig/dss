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
import eu.europa.esig.dss.validation.process.bbb.fc.checks.TimestampFilenameAdherenceCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TimestampFilenameAdherenceCheckTest extends AbstractTestCheck {

    @Test
    void asicsTstValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTstWithPrefixInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/prefix_timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTstWithSuffixInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp_suffix.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTstWithPrefixWithArchManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/prefix_timestamp.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsTstWithSuffixWithArchManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp_suffix.tst");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlTimestamp.getTimestampFilename());
        xmlManifestFile.setFilename("META-INF/ASiCArchiveManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstWithPrefixValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/prefix_timestamp.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstWithSuffixValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/timestamp_suffix.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceTstWithPrefixAndSuffixValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setTimestampFilename("META-INF/prefix_timestamp_suffix.tst");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        TimestampFilenameAdherenceCheck tfac = new TimestampFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        tfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
