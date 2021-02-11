package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQCLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateMinQcTransactionLimitCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateMinQcTransactionLimitCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlQCLimitValue xmlQCLimitValue = new XmlQCLimitValue();
        xmlQCLimitValue.setAmount(1000);
        xmlQCLimitValue.setExponent(3);
        xmlQcStatements.setQcLimitValue(xmlQCLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void sameNumberTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlQCLimitValue xmlQCLimitValue = new XmlQCLimitValue();
        xmlQCLimitValue.setAmount(1000);
        xmlQCLimitValue.setExponent(3);
        xmlQcStatements.setQcLimitValue(xmlQCLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(1000000);

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlQCLimitValue xmlQCLimitValue = new XmlQCLimitValue();
        xmlQCLimitValue.setAmount(1000);
        xmlQCLimitValue.setExponent(3);
        xmlQcStatements.setQcLimitValue(xmlQCLimitValue);

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(5000000);

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcLimitValueNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcStatementsNotPresentTest() throws Exception {
        IntValueConstraint constraint = new IntValueConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.setValue(500000);

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateMinQcTransactionLimitCheck cmqctlc = new CertificateMinQcTransactionLimitCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cmqctlc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
