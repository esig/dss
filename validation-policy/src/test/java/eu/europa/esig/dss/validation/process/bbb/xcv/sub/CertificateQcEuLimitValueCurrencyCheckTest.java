package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcEuLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQcEuLimitValueCurrencyCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateQcEuLimitValueCurrencyCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency("EUR");
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlQcEuLimitValue xmlQcEuLimitValue = new XmlQcEuLimitValue();
        xmlQcEuLimitValue.setCurrency("EUR");
        xmlQcStatements.setQcEuLimitValue(xmlQcEuLimitValue);

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("AUD");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcLimitValueNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcStatementsNotPresentTest() throws Exception {
        ValueConstraint constraint = new ValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue("EUR");

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateQcEuLimitValueCurrencyCheck cqctlcc = new CertificateQcEuLimitValueCurrencyCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cqctlcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
