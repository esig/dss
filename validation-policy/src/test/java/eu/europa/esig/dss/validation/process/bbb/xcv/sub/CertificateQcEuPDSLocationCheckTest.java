package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcEuPDSLocationCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateQcEuPDSLocationCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlLangAndValue langAndValueEn = new XmlLangAndValue();
        langAndValueEn.setLang("en");
        langAndValueEn.setValue("https://repository.eid.belgium.be");
        XmlLangAndValue langAndValueFr = new XmlLangAndValue();
        langAndValueFr.setLang("fr");
        langAndValueFr.setValue("https://repository.eid.belgium.be/fr/");
        xmlQcStatements.setQcEuPDS(Arrays.asList(langAndValueEn, langAndValueFr));

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("https://repository.eid.belgium.be");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuPDSLocationCheck cqcpdslc = new CertificateQcEuPDSLocationCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cqcpdslc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlLangAndValue langAndValueEn = new XmlLangAndValue();
        langAndValueEn.setLang("en");
        langAndValueEn.setValue("https://repository.eid.lux.lu");
        XmlLangAndValue langAndValueFr = new XmlLangAndValue();
        langAndValueFr.setLang("fr");
        langAndValueFr.setValue("https://repository.eid.lux.lu/fr/");
        xmlQcStatements.setQcEuPDS(Arrays.asList(langAndValueEn, langAndValueFr));

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("https://repository.eid.belgium.be");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuPDSLocationCheck cqcpdslc = new CertificateQcEuPDSLocationCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cqcpdslc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcPDSNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("https://repository.eid.belgium.be");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuPDSLocationCheck cqcpdslc = new CertificateQcEuPDSLocationCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cqcpdslc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcStatementsNotPresentTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("https://repository.eid.belgium.be");

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuPDSLocationCheck cqcpdslc = new CertificateQcEuPDSLocationCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cqcpdslc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
