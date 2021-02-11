package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Info;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePS2DQcCompetentAuthorityNameCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificatePS2DQcCompetentAuthorityNameCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlPSD2Info xmlPSD2Info = new XmlPSD2Info();
        xmlPSD2Info.setNcaName("CSSF");
        xmlQcStatements.setPSD2Info(xmlPSD2Info);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("CSSF");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePS2DQcCompetentAuthorityNameCheck cqcps2dnc = new CertificatePS2DQcCompetentAuthorityNameCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcps2dnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleValuesTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlPSD2Info xmlPSD2Info = new XmlPSD2Info();
        xmlPSD2Info.setNcaName("CSSF");
        xmlQcStatements.setPSD2Info(xmlPSD2Info);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("NBB");
        constraint.getId().add("CSSF");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePS2DQcCompetentAuthorityNameCheck cqcps2dnc = new CertificatePS2DQcCompetentAuthorityNameCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcps2dnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlPSD2Info xmlPSD2Info = new XmlPSD2Info();
        xmlPSD2Info.setNcaName("NBB");
        xmlQcStatements.setPSD2Info(xmlPSD2Info);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("CSSF");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePS2DQcCompetentAuthorityNameCheck cqcps2dnc = new CertificatePS2DQcCompetentAuthorityNameCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcps2dnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcPS2DNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("CSSF");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificatePS2DQcCompetentAuthorityNameCheck cqcps2dnc = new CertificatePS2DQcCompetentAuthorityNameCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcps2dnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcStatementsNotPresentTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("CSSF");

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificatePS2DQcCompetentAuthorityNameCheck cqcps2dnc = new CertificatePS2DQcCompetentAuthorityNameCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqcps2dnc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
