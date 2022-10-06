package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfSignatureDictionaryCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PdfSignatureDictionaryCheckTest extends AbstractTestCheck {

    @Test
    public void valid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfSignatureDictionary.setConsistent(true);
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        PdfSignatureDictionaryCheck sdc = new PdfSignatureDictionaryCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        sdc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() throws Exception {
        XmlSignature xmlSignature = new XmlSignature();

        XmlPDFRevision pdfRevision = new XmlPDFRevision();
        xmlSignature.setPDFRevision(pdfRevision);

        XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
        pdfSignatureDictionary.setConsistent(false);
        pdfRevision.setPDFSignatureDictionary(pdfSignatureDictionary);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        PdfSignatureDictionaryCheck sdc = new PdfSignatureDictionaryCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), constraint);
        sdc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
