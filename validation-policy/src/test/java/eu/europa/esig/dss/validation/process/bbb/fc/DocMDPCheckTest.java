/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.DocMDPCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DocMDPCheckTest extends AbstractTestCheck {

    @Test
    public void noChangesPermittedValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

        XmlModificationDetection modificationDetection = new XmlModificationDetection();
        pdfRevision.setModificationDetection(modificationDetection);

        XmlObjectModifications objectModifications = new XmlObjectModifications();
        modificationDetection.setObjectModifications(objectModifications);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModifications.getExtensionChanges().add(objectModification);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void noChangesPermittedFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

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
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void minimalChangesPermittedValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

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
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void minimalChangesPermittedFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.MINIMAL_CHANGES_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

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
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void changesPermittedValid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.CHANGES_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

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
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void changesPermittedFail() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlDocMDP docMDP = new XmlDocMDP();
        docMDP.setPermissions(CertificationPermission.CHANGES_PERMITTED);
        pdfSignatureDictionary.setDocMDP(docMDP);

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
        DocMDPCheck dmdpc = new DocMDPCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        dmdpc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
