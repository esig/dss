package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ManifestFilePresentCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ManifestFilePresentCheckTest extends AbstractTestCheck {

    @Test
    public void asicsWithManifestTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setManifestFiles(Collections.singletonList(new XmlManifestFile()));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void asicsNoManifestTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setManifestFiles(Collections.emptyList());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void asicsNoManifestNullTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
        xmlContainerInfo.setManifestFiles(null);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void asiceWithManifestTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setManifestFiles(Collections.singletonList(new XmlManifestFile()));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void asiceNoManifestTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setManifestFiles(Collections.emptyList());

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void asiceNoManifestNullTest() {
        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
        xmlContainerInfo.setManifestFiles(null);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ManifestFilePresentCheck mfpc = new ManifestFilePresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
        mfpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
