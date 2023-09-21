package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuerNameCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateIssuerNameCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test2,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void diffOrder() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("OU=permittedSubtree1,CN=Valid DN nameConstraints CA Certificate Test1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void missedAttr() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void selfSignedValid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        signingCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void selfSignedInvalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        signingCertificate.setSelfSigned(true);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void sameDNNotSelfSignedValid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void sameDNNotSelfSignedInvalid() {
        XmlCertificate signingCertificate = new XmlCertificate();
        XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        signingCertificate.getIssuerDistinguishedName().add(xmlDistinguishedName);

        XmlCertificate caCertificate = new XmlCertificate();
        xmlDistinguishedName = new XmlDistinguishedName();
        xmlDistinguishedName.setFormat("RFC2253");
        xmlDistinguishedName.setValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US");
        caCertificate.getSubjectDistinguishedName().add(xmlDistinguishedName);

        XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
        xmlSigningCertificate.setCertificate(caCertificate);
        signingCertificate.setSigningCertificate(xmlSigningCertificate);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlSubXCV result = new XmlSubXCV();
        CertificateIssuerNameCheck cinc = new CertificateIssuerNameCheck(i18nProvider, result,
                new CertificateWrapper(signingCertificate), constraint);
        cinc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}