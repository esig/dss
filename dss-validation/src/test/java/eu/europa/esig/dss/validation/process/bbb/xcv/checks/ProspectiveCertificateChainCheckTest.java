package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ProspectiveCertificateChainCheckTest extends AbstractTestCheck {

    @Test
    void certTrustedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void certNotTrustedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(false);
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void certTrustedOtherTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getSources().add(CertificateSourceType.OTHER);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void certNotTrustedTrustedListTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getSources().add(CertificateSourceType.TRUSTED_LIST);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(false);
        xc.setTrusted(xmlTrusted);

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void trustStoreChainTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        ca.getSources().add(CertificateSourceType.TRUSTED_STORE);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void trustedListChainTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        ca.getSources().add(CertificateSourceType.TRUSTED_LIST);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void otherTrustedChainTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        ca.getSources().add(CertificateSourceType.OTHER);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(true);
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void trustStoreChainNotTrustedTest() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        ca.getSources().add(CertificateSourceType.TRUSTED_STORE);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(false);
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlXCV result = new XmlXCV();
        ProspectiveCertificateChainCheck<XmlXCV> pccc = new ProspectiveCertificateChainCheck<>(i18nProvider, result,
                new CertificateWrapper(xc), Context.CERTIFICATE, constraint);
        pccc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
