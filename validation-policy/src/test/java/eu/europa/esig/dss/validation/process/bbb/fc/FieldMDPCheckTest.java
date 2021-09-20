package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FieldMDPCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FieldMDPCheckTest extends AbstractTestCheck {

    @Test
    public void allFieldsLockedValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.ALL);
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void allFieldsLockedFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.ALL);
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setFieldName("Signature2");
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void exclusiveFieldLockValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.EXCLUDE);
        fieldMDP.getFields().add("Signature2");
        fieldMDP.getFields().add("Signature3");
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setFieldName("Signature2");
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void exclusiveFieldLockFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.EXCLUDE);
        fieldMDP.getFields().add("Signature2");
        fieldMDP.getFields().add("Signature3");
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setFieldName("Signature2");
        objectModifications.getSignatureOrFormFill().add(objectModification);

        XmlObjectModification objectModificationTwo = new XmlObjectModification();
        objectModificationTwo.setFieldName("Signature4");
        objectModifications.getSignatureOrFormFill().add(objectModificationTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void inclusiveFieldLockValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.INCLUDE);
        fieldMDP.getFields().add("Signature2");
        fieldMDP.getFields().add("Signature3");
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setFieldName("Signature4");
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void inclusiveFieldLockFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlPDFLockDictionary fieldMDP = new XmlPDFLockDictionary();
        fieldMDP.setAction(PdfLockAction.INCLUDE);
        fieldMDP.getFields().add("Signature2");
        fieldMDP.getFields().add("Signature3");
        pdfSignatureDictionary.setFieldMDP(fieldMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setFieldName("Signature2");
        objectModifications.getSignatureOrFormFill().add(objectModification);

        XmlObjectModification objectModificationTwo = new XmlObjectModification();
        objectModificationTwo.setFieldName("Signature4");
        objectModifications.getSignatureOrFormFill().add(objectModificationTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        FieldMDPCheck fmdpc = new FieldMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        fmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
