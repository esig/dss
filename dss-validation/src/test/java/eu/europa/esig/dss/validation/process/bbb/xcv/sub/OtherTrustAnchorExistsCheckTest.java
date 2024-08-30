package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrusted;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OtherTrustAnchorExistsCheck;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OtherTrustAnchorExistsCheckTest extends AbstractTestCheck {

    @Test
    void trustStoreTest() {
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

        XmlSubXCV result = new XmlSubXCV();
        OtherTrustAnchorExistsCheck otsc = new OtherTrustAnchorExistsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        otsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void trustedList() {
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

        XmlSubXCV result = new XmlSubXCV();
        OtherTrustAnchorExistsCheck otsc = new OtherTrustAnchorExistsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        otsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void notTrusted() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();

        XmlCertificate ca = new XmlCertificate();
        ca.getSources().add(CertificateSourceType.SIGNATURE);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(false);
        ca.setTrusted(xmlTrusted);

        XmlChainItem xmlChainItem = new XmlChainItem();
        xmlChainItem.setCertificate(ca);
        xc.setCertificateChain(Collections.singletonList(xmlChainItem));

        XmlSubXCV result = new XmlSubXCV();
        OtherTrustAnchorExistsCheck otsc = new OtherTrustAnchorExistsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        otsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notCa() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCertificate xc = new XmlCertificate();
        xc.getSources().add(CertificateSourceType.TRUSTED_STORE);
        XmlTrusted xmlTrusted = new XmlTrusted();
        xmlTrusted.setValue(false);
        xc.setTrusted(xmlTrusted);

        XmlSubXCV result = new XmlSubXCV();
        OtherTrustAnchorExistsCheck otsc = new OtherTrustAnchorExistsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        otsc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
