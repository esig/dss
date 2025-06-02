package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureManifestFilenameAdherenceCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureManifestFilenameAdherenceCheckTest extends AbstractTestCheck {

    @Test
    void asicsXmlSigNoManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsXmlSigManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsXmlSigDiffManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/man.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceXmlSigNoManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceXmlSigManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceXmlSigDiffManifestInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signatures.xml");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/man.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsCadesSigNoManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsCadesSigManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asicsCadesSigDiffManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asieCadesSigNoManifestInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceCadesSigManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceCadesSigDiffManifestValidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/ASiCManifest001.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void asiceCadesSigManifestInvalidTest() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
        xmlDiagnosticData.setContainerInfo(xmlContainerInfo);
        xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setSignatureFormat(SignatureLevel.CAdES_BASELINE_B);
        xmlSignature.setSignatureFilename("META-INF/signature.p7s");

        XmlManifestFile xmlManifestFile = new XmlManifestFile();
        xmlManifestFile.setSignatureFilename(xmlSignature.getSignatureFilename());
        xmlManifestFile.setFilename("META-INF/manifest.xml");
        xmlContainerInfo.setManifestFiles(Collections.singletonList(xmlManifestFile));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SignatureManifestFilenameAdherenceCheck smfac = new SignatureManifestFilenameAdherenceCheck(i18nProvider, result,
                new DiagnosticData(xmlDiagnosticData), new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
        smfac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
