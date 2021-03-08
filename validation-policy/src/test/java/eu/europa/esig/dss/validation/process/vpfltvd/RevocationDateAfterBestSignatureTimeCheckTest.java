package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationDateAfterBestSignatureTimeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class RevocationDateAfterBestSignatureTimeCheckTest extends AbstractTestCheck {

    @Test
    public void validTest() throws Exception {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil + 43200000)); // 12 hours after

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        RevocationDateAfterBestSignatureTimeCheck rdabstc = new RevocationDateAfterBestSignatureTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint, SubContext.SIGNING_CERT);
        rdabstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNull(conclusion);

    }

    @Test
    public void invalidTest() throws Exception {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil - 43200000)); // 12 hours before

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        RevocationDateAfterBestSignatureTimeCheck rdabstc = new RevocationDateAfterBestSignatureTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint, SubContext.SIGNING_CERT);
        rdabstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, conclusion.getSubIndication());

    }

    @Test
    public void invalidCATest() throws Exception {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil - 43200000)); // 12 hours before

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        RevocationDateAfterBestSignatureTimeCheck rdabstc = new RevocationDateAfterBestSignatureTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint, SubContext.CA_CERTIFICATE);
        rdabstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.REVOKED_CA_NO_POE, conclusion.getSubIndication());

    }

    @Test
    public void sameTimeTest() throws Exception {

        Date bestSignatureTime = new Date();

        XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
        xmlCertificateRevocation.setRevocation(new XmlRevocation());
        long nowMil = bestSignatureTime.getTime();
        xmlCertificateRevocation.setRevocationDate(new Date(nowMil)); // same time

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlValidationProcessLongTermData result = new XmlValidationProcessLongTermData();
        RevocationDateAfterBestSignatureTimeCheck rdabstc = new RevocationDateAfterBestSignatureTimeCheck(
                i18nProvider, result, new CertificateRevocationWrapper(xmlCertificateRevocation), bestSignatureTime,
                constraint, SubContext.SIGNING_CERT);
        rdabstc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

        XmlConclusion conclusion = result.getConclusion();
        assertNotNull(conclusion);
        assertEquals(Indication.INDETERMINATE, conclusion.getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, conclusion.getSubIndication());

    }

}
