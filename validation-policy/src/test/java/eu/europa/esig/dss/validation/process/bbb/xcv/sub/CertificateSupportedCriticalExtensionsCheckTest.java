package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSupportedCriticalExtensionsCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateSupportedCriticalExtensionsCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        constraint.getId().add(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notCriticalTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        XmlCertificateExtension certificateExtensionNotCritical = new XmlCertificateExtension();
        certificateExtensionNotCritical.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        certificateExtensionNotCritical.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionNotCritical);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        constraint.getId().add(CertificateExtensionEnum.QC_STATEMENTS.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void notCriticalExtensionsTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        XmlCertificateExtension certificateExtensionNotCritical = new XmlCertificateExtension();
        certificateExtensionNotCritical.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        certificateExtensionNotCritical.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionNotCritical);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void notExtensionsTest() {
        XmlCertificate xc = new XmlCertificate();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.KEY_USAGE.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void noConstraintsDefinedTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(true);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void noConstraintsDefinedNoCriticalTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        certificateExtensionOne.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        certificateExtensionTwo.setCritical(false);
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateSupportedCriticalExtensionsCheck cscec = new CertificateSupportedCriticalExtensionsCheck(
                i18nProvider, result, new CertificateWrapper(xc), constraint);
        cscec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }


}
