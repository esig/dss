package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.OrganizationUnitCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class OrganizationUnitCheckTest {

	@Test
	public void organizationUnitCheck() throws Exception {
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Org");

		XmlCertificate xc = new XmlCertificate();
		xc.setOrganizationalUnit("Valid_Org");

		XmlSubXCV result = new XmlSubXCV();
		OrganizationUnitCheck ouc = new OrganizationUnitCheck(result, new CertificateWrapper(xc), constraint);
		ouc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedOrganizationUnitCheck() throws Exception {
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Invalid_Org");

		XmlCertificate xc = new XmlCertificate();
		xc.setOrganizationalUnit("Valid_Org");

		XmlSubXCV result = new XmlSubXCV();
		OrganizationUnitCheck ouc = new OrganizationUnitCheck(result, new CertificateWrapper(xc), constraint);
		ouc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
