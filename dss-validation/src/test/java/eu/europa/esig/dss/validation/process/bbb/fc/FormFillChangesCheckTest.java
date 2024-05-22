package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormFillChangesCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FormFillChangesCheckTest extends AbstractTestCheck {

    @Test
    public void noChangesTest() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FormFillChangesCheck ffcc = new FormFillChangesCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        ffcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void identifiedChangesTest() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        objectModifications.getExtensionChanges().add(new XmlObjectModification());
        modificationDetection.setObjectModifications(objectModifications);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FormFillChangesCheck ffcc = new FormFillChangesCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        ffcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void formFillChangesTest() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        objectModifications.getExtensionChanges().add(new XmlObjectModification());
        objectModifications.getSignatureOrFormFill().add(new XmlObjectModification());
        modificationDetection.setObjectModifications(objectModifications);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FormFillChangesCheck ffcc = new FormFillChangesCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        ffcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}