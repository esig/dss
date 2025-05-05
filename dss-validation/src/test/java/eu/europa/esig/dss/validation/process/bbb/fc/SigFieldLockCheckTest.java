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
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SigFieldLockCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SigFieldLockCheckTest extends AbstractTestCheck {

    @Test
    void allFieldsLockedValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void allFieldsLockedFail() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        signatureField.setSigFieldLock(sigFieldLock);

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
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void exclusiveFieldLockValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.EXCLUDE);
        sigFieldLock.getFields().add("Signature2");
        sigFieldLock.getFields().add("Signature3");
        signatureField.setSigFieldLock(sigFieldLock);

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
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void exclusiveFieldLockFail() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.EXCLUDE);
        sigFieldLock.getFields().add("Signature2");
        sigFieldLock.getFields().add("Signature3");
        signatureField.setSigFieldLock(sigFieldLock);

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
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void inclusiveFieldLockValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.INCLUDE);
        sigFieldLock.getFields().add("Signature2");
        sigFieldLock.getFields().add("Signature3");
        signatureField.setSigFieldLock(sigFieldLock);

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
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void inclusiveFieldLockFail() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.INCLUDE);
        sigFieldLock.getFields().add("Signature2");
        sigFieldLock.getFields().add("Signature3");
        signatureField.setSigFieldLock(sigFieldLock);

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
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noChangesAllowedValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void noChangesAllowedFail(){
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void minimalChangesAllowedValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);
        objectModifications.getSignatureOrFormFill().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void minimalChangesAllowedFail() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);
        objectModifications.getSignatureOrFormFill().add(objectModification);
        objectModifications.getAnnotationChanges().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void changesAllowedValid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.CHANGES_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);
        objectModifications.getSignatureOrFormFill().add(objectModification);
        objectModifications.getAnnotationChanges().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void changesAllowedFail() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureField signatureField = new XmlPDFSignatureField();
        pdfRevision.getFields().add(signatureField);

        XmlPDFLockDictionary sigFieldLock = new XmlPDFLockDictionary();
        sigFieldLock.setAction(PdfLockAction.ALL);
        sigFieldLock.setPermissions(CertificationPermission.CHANGES_PERMITTED);
        signatureField.setSigFieldLock(sigFieldLock);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);
        objectModifications.getSignatureOrFormFill().add(objectModification);
        objectModifications.getAnnotationChanges().add(objectModification);
        objectModifications.getUndefined().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        SigFieldLockCheck sflc = new SigFieldLockCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), new LevelConstraintWrapper(constraint));
        sflc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
