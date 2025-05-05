package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationAfterCertificateIssuanceCheck;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationAfterCertificateIssuanceCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(new Date());

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, -1);
        xmlCertificate.setNotBefore(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationAfterCertificateIssuanceCheck rikcc = new RevocationAfterCertificateIssuanceCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rikcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(new Date());

        Calendar calendar = Calendar.getInstance();
        XmlCertificate xmlCertificate = new XmlCertificate();

        calendar.add(Calendar.YEAR, 1);
        xmlCertificate.setNotBefore(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationAfterCertificateIssuanceCheck rikcc = new RevocationAfterCertificateIssuanceCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rikcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void atThisUpdateTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        Calendar calendar = Calendar.getInstance();

        XmlRevocation xmlRevocation = new XmlRevocation();
        xmlRevocation.setThisUpdate(calendar.getTime());

        XmlCertificate xmlCertificate = new XmlCertificate();
        xmlCertificate.setNotBefore(calendar.getTime());

        XmlRAC result = new XmlRAC();
        RevocationAfterCertificateIssuanceCheck rikcc = new RevocationAfterCertificateIssuanceCheck(i18nProvider, result,
                new CertificateWrapper(xmlCertificate), new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
        rikcc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
