package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ByteRangeCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(true);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCheck brc = new ByteRangeCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        brc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        byteRange.setValid(false);
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCheck brc = new ByteRangeCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        brc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void validityNotDefinedTest() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        XmlByteRange byteRange = new XmlByteRange();
        pdfSignatureDictionary.setSignatureByteRange(byteRange);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCheck brc = new ByteRangeCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        brc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noByteRangeTest() {
        XmlPDFRevision pdfRevision = new XmlPDFRevision();

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        ByteRangeCheck brc = new ByteRangeCheck(i18nProvider, result, new PDFRevisionWrapper(pdfRevision), constraint);
        brc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
