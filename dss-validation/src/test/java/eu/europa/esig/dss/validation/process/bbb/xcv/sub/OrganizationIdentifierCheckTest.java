package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationIdentifierCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OrganizationIdentifierCheckTest extends AbstractTestCheck {

    @Test
    public void validCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("Valid_Org_Identifier");

        XmlCertificate xc = new XmlCertificate();
        xc.setOrganizationIdentifier("Valid_Org_Identifier");

        XmlSubXCV result = new XmlSubXCV();
        OrganizationIdentifierCheck oic = new OrganizationIdentifierCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        oic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    public void invalidCheck() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.setLevel(Level.FAIL);
        constraint.getId().add("Valid_Org_Identifier");

        XmlCertificate xc = new XmlCertificate();
        xc.setOrganizationIdentifier("Invalid_Org_Identifier");

        XmlSubXCV result = new XmlSubXCV();
        OrganizationIdentifierCheck oic = new OrganizationIdentifierCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
        oic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
