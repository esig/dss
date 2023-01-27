package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlExtendedKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.ExtendedKeyUsageCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExtendedKeyUsageCheckTest extends AbstractTestCheck {

    @Test
    public void valid() {
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription(ExtendedKeyUsage.TIMESTAMPING.getDescription());
        xmlExtendedKeyUsages.getExtendedKeyUsagesOid().add(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(ExtendedKeyUsage.TIMESTAMPING.getDescription());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlExtendedKeyUsages);

        XmlSubXCV result = new XmlSubXCV();
        ExtendedKeyUsageCheck ekuc = new ExtendedKeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc),
                Context.TIMESTAMP, SubContext.SIGNING_CERT, constraint);
        ekuc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalid() {
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
        XmlOID xmlOID = new XmlOID();
        xmlOID.setDescription(ExtendedKeyUsage.TIMESTAMPING.getDescription());
        xmlExtendedKeyUsages.getExtendedKeyUsagesOid().add(xmlOID);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("invalidKey");

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlExtendedKeyUsages);

        XmlSubXCV result = new XmlSubXCV();
        ExtendedKeyUsageCheck ekuc = new ExtendedKeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc),
                Context.TIMESTAMP, SubContext.SIGNING_CERT, constraint);
        ekuc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    public void multiValuesCheck() {
        XmlExtendedKeyUsages xmlExtendedKeyUsages = new XmlExtendedKeyUsages();
        xmlExtendedKeyUsages.setOID(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());

        XmlOID xmlOIDOne = new XmlOID();
        xmlOIDOne.setDescription(ExtendedKeyUsage.OCSP_SIGNING.getDescription());
        xmlExtendedKeyUsages.getExtendedKeyUsagesOid().add(xmlOIDOne);

        XmlOID xmlOIDTwo = new XmlOID();
        xmlOIDTwo.setDescription(ExtendedKeyUsage.TSL_SIGNING.getDescription());
        xmlExtendedKeyUsages.getExtendedKeyUsagesOid().add(xmlOIDTwo);

        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add(ExtendedKeyUsage.OCSP_SIGNING.getDescription());

        XmlCertificate xc = new XmlCertificate();
        xc.getCertificateExtensions().add(xmlExtendedKeyUsages);

        XmlSubXCV result = new XmlSubXCV();
        ExtendedKeyUsageCheck ekuc = new ExtendedKeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc),
                Context.REVOCATION, SubContext.SIGNING_CERT, constraint);
        ekuc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
