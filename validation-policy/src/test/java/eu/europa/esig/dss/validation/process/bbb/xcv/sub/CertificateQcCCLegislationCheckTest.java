package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcCCLegislationCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateQcCCLegislationCheckTest extends AbstractTestCheck {

    @Test
    public void euQualifiedCertificateTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void euNotQualifiedCertificateTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("CR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUQualifiedCertificateTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("CR");
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("CR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUNotQualifiedCertificateTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("CR");
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("BR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUAcceptAllCertificateTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("*");
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("BR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUMultiValuesTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().addAll(Arrays.asList("AU", "BR", "CR", "US"));
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("BR", "CR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUMixedOrderTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().addAll(Arrays.asList("AU", "BR", "CR", "US"));
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("BR", "CR", "FR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void nonEUMixedOrderFailTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().addAll(Arrays.asList("AU", "US"));
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlQcStatements xmlQcStatements = new XmlQcStatements();
        xmlQcStatements.setQcCClegislation(Arrays.asList("BR", "CR", "FR"));
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcCCLegislationCheck cqcclc = new CertificateQcCCLegislationCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcclc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
