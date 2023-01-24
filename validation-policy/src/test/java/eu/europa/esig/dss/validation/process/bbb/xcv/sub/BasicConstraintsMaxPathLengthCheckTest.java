package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.BasicConstraintsMaxPathLengthCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicConstraintsMaxPathLengthCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void notDefinedCheck() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void selfSignedTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        rootCertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(rootCertificate);
        caCertificate.setCertificateChain(Collections.singletonList(xmlChainItem));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void longChainTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void longChainEnforcedTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(2);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void longChainInvalidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void decreasingDepthTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(2);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void decreasingDepthValidTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(3);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void increasingDepthTest() {
        XmlCertificate rootCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        rootCertificate.getCertificateExtensions().add(basicConstraints);
        rootCertificate.setSelfSigned(true);

        XmlCertificate intermediateCACertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(1);
        intermediateCACertificate.getCertificateExtensions().add(basicConstraints);

        XmlCertificate caCertificate = new XmlCertificate();
        basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        XmlChainItem xmlChainItemOne = new XmlChainItem();
        xmlChainItemOne.setCertificate(rootCertificate);
        XmlChainItem xmlChainItemTwo = new XmlChainItem();
        xmlChainItemTwo.setCertificate(intermediateCACertificate);
        caCertificate.setCertificateChain(Arrays.asList(xmlChainItemTwo, xmlChainItemOne));

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void oneCertTest() {
        XmlCertificate caCertificate = new XmlCertificate();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void oneCertCATest() {
        XmlCertificate caCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void oneCertSelfSignedTest() {
        XmlCertificate caCertificate = new XmlCertificate();
        caCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void oneCertSelfSignedCATest() {
        XmlCertificate caCertificate = new XmlCertificate();
        XmlBasicConstraints basicConstraints = new XmlBasicConstraints();
        basicConstraints.setCA(true);
        basicConstraints.setPathLenConstraint(0);
        caCertificate.getCertificateExtensions().add(basicConstraints);
        caCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        BasicConstraintsMaxPathLengthCheck bcmaplc = new BasicConstraintsMaxPathLengthCheck(i18nProvider, result,
                new CertificateWrapper(caCertificate), constraint);
        bcmaplc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
