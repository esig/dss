package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.BasicConstraintsCACheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicConstraintsCACheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.setBasicConstraints(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsCACheck bccac = new BasicConstraintsCACheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        bccac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(false);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.setBasicConstraints(basicConstraints);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsCACheck bccac = new BasicConstraintsCACheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        bccac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void notPresentTest() {

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsCACheck bccac = new BasicConstraintsCACheck(i18nProvider, result,
                new CertificateWrapper(xc), constraint);
        bccac.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
