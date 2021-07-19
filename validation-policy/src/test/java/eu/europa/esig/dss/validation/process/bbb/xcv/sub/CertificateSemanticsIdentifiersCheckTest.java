package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSemanticsIdentifierCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateSemanticsIdentifiersCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for natural person");
        xmlOID.setValue("0.4.0.194121.1.1");

        xmlQcStatements.setSemanticsIdentifier(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("0.4.0.194121.1.1");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void multipleValuesTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for natural person");
        xmlOID.setValue("0.4.0.194121.1.1");

        xmlQcStatements.setSemanticsIdentifier(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("0.4.0.194121.1.1");
        constraint.getId().add("0.4.0.194121.1.3");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void nameTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for legal person");
        xmlOID.setValue("0.4.0.194121.1.2");

        xmlQcStatements.setSemanticsIdentifier(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("qcs-SemanticsId-Legal");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription("Semantics identifier for legal person");
        xmlOID.setValue("0.4.0.194121.1.1");

        xmlQcStatements.setSemanticsIdentifier(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("0.4.0.194121.1.3");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcPS2DNotPresentTest() throws Exception {
        XmlQcStatements xmlQcStatements = new XmlQcStatements();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("0.4.0.194121.1.4");

        XmlCertificate xc = new XmlCertificate();
        xc.setQcStatements(xmlQcStatements);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void qcStatementsNotPresentTest() throws Exception {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("0.4.0.194121.1.4");

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        CertificateSemanticsIdentifierCheck csic = new CertificateSemanticsIdentifierCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        csic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
