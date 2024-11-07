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
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeAllDocumentCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ByteRangeAllDocumentCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlSignature xmlSignatureTwo = new XmlSignature();

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureTwo.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getSignatures().add(xmlSignatureTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeAllDocumentCheck brcc = new ByteRangeAllDocumentCheck(i18nProvider, result, new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlSignature xmlSignatureTwo = new XmlSignature();

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.setValid(false);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureTwo.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getSignatures().add(xmlSignatureTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeAllDocumentCheck brcc = new ByteRangeAllDocumentCheck(i18nProvider, result, new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validWithTimestamp() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlTimestamp.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getUsedTimestamps().add(xmlTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeAllDocumentCheck brcc = new ByteRangeAllDocumentCheck(i18nProvider, result, new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidWithTimestamp() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.setValid(false);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlTimestamp.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getUsedTimestamps().add(xmlTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeAllDocumentCheck brcc = new ByteRangeAllDocumentCheck(i18nProvider, result, new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validWithSignatureTimestamp() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlDiagnosticData.getUsedTimestamps().add(xmlTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeAllDocumentCheck brcc = new ByteRangeAllDocumentCheck(i18nProvider, result, new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
