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
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeCollisionCheck;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ByteRangeCollisionCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();
        xmlSignatureOne.setId("SignatureOne");

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(840), BigInteger.valueOf(960), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlSignature xmlSignatureTwo = new XmlSignature();
        xmlSignatureTwo.setId("SignatureTwo");

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(1440), BigInteger.valueOf(1560), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureTwo.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getSignatures().add(xmlSignatureTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCollisionCheck brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignatureOne), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        result = new XmlFC();
        brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignatureTwo), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignatureOne = new XmlSignature();
        xmlSignatureOne.setId("SignatureOne");

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(840), BigInteger.valueOf(960), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureOne.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignatureOne);

        XmlSignature xmlSignatureTwo = new XmlSignature();
        xmlSignatureTwo.setId("SignatureTwo");

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(1040), BigInteger.valueOf(1160), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignatureTwo.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getSignatures().add(xmlSignatureTwo);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCollisionCheck brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignatureOne), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        result = new XmlFC();
        brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignatureTwo), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void validWithTimestamp() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setId("SignatureOne");

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(840), BigInteger.valueOf(960), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignature.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignature);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setId("TimestampOne");

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(1440), BigInteger.valueOf(1560), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlTimestamp.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getUsedTimestamps().add(xmlTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCollisionCheck brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignature), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        result = new XmlFC();
        brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new TimestampWrapper(xmlTimestamp), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidWithTimestamp() {
        XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();

        XmlSignature xmlSignature = new XmlSignature();
        xmlSignature.setId("SignatureOne");

        XmlPDFRevision pdfRevisionOne = new XmlPDFRevision();
        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionOne.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(840), BigInteger.valueOf(960), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlSignature.setPDFRevision(pdfRevisionOne);
        xmlDiagnosticData.getSignatures().add(xmlSignature);

        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setId("TimestampOne");

        XmlPDFRevision pdfRevisionTwo = new XmlPDFRevision();
        pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevisionTwo.setPDFSignatureDictionary(pdfSignatureDictionary);

        byteRange = new XmlByteRange();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(1040), BigInteger.valueOf(1160), BigInteger.valueOf(240)));
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        xmlTimestamp.setPDFRevision(pdfRevisionTwo);
        xmlDiagnosticData.getUsedTimestamps().add(xmlTimestamp);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCollisionCheck brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new SignatureWrapper(xmlSignature), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        result = new XmlFC();
        brcc = new ByteRangeCollisionCheck(i18nProvider, result,
                new TimestampWrapper(xmlTimestamp), new DiagnosticData(xmlDiagnosticData), constraint);
        brcc.execute();

        constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
