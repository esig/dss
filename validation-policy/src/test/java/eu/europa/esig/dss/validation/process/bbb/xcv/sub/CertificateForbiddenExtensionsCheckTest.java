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
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateForbiddenExtensionsCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateForbiddenExtensionsCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateForbiddenExtensionsCheck cfec = new CertificateForbiddenExtensionsCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cfec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateForbiddenExtensionsCheck cfec = new CertificateForbiddenExtensionsCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cfec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void emptyExtensionsTest() {
        XmlCertificate xc = new XmlCertificate();

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(CertificateExtensionEnum.OCSP_NOCHECK.getOid());

        XmlSubXCV result = new XmlSubXCV();
        CertificateForbiddenExtensionsCheck cfec = new CertificateForbiddenExtensionsCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cfec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void emptyConstraintTest() {
        XmlCertificate xc = new XmlCertificate();

        XmlCertificateExtension certificateExtensionOne = new XmlCertificateExtension();
        certificateExtensionOne.setOID(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
        xc.getCertificateExtensions().add(certificateExtensionOne);

        XmlCertificateExtension certificateExtensionTwo = new XmlCertificateExtension();
        certificateExtensionTwo.setOID(CertificateExtensionEnum.QC_STATEMENTS.getOid());
        xc.getCertificateExtensions().add(certificateExtensionTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateForbiddenExtensionsCheck cfec = new CertificateForbiddenExtensionsCheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        cfec.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
