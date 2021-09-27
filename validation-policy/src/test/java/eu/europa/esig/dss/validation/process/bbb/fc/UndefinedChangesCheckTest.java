package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.UndefinedChangesCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UndefinedChangesCheckTest extends AbstractTestCheck {

    @Test
    public void noChangesTest() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        UndefinedChangesCheck ucc = new UndefinedChangesCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ucc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void identifiedChangesTest() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        objectModifications.getExtensionChanges().add(new XmlObjectModification());
        objectModifications.getSignatureOrFormFill().add(new XmlObjectModification());
        modificationDetection.setObjectModifications(objectModifications);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        UndefinedChangesCheck ucc = new UndefinedChangesCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ucc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void undefinedChangesTest() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        objectModifications.getExtensionChanges().add(new XmlObjectModification());
        objectModifications.getSignatureOrFormFill().add(new XmlObjectModification());
        objectModifications.getUndefined().add(new XmlObjectModification());
        modificationDetection.setObjectModifications(objectModifications);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        UndefinedChangesCheck ucc = new UndefinedChangesCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        ucc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}