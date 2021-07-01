package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerValidityRangeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RevocationIssuerValidityRangeCheckTest extends AbstractTestCheck {

    @Test
    public void validCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();

        Date now = new Date();
        long nowMil = now.getTime();
        XmlCertificate xc = new XmlCertificate();
        xc.setNotAfter(new Date(nowMil + 86400000)); // in 24 hours
        xc.setNotBefore(new Date(nowMil - 86400000)); // 24 hours ago

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xc);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlSubXCV result = new XmlSubXCV();
        RevocationIssuerValidityRangeCheck<XmlSubXCV> rivrc = new RevocationIssuerValidityRangeCheck<>(
                i18nProvider, result,  new RevocationWrapper(xmlRevocation), new Date(), constraint);
        rivrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void failCheck() throws Exception {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlRevocation xmlRevocation = new XmlRevocation();

        Date now = new Date();
        long nowMil = now.getTime();
        XmlCertificate xc = new XmlCertificate();
        xc.setNotAfter(new Date(nowMil - 86400000)); // 24 hours ago
        xc.setNotBefore(new Date(nowMil - 172800000)); // 48 hours ago

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(xc);

        xmlRevocation.setSigningCertificate(xmlSigningCertificate);

        XmlSubXCV result = new XmlSubXCV();
        RevocationIssuerValidityRangeCheck<XmlSubXCV> rivrc = new RevocationIssuerValidityRangeCheck<>(
                i18nProvider, result,  new RevocationWrapper(xmlRevocation), new Date(), constraint);
        rivrc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
