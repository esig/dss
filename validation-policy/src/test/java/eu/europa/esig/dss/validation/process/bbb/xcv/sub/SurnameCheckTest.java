package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.SurnameCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class SurnameCheckTest {

	@Test
	public void surnameCheck() throws Exception {
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Surname");

		XmlCertificate xc = new XmlCertificate();
		xc.setSurname("Valid_Surname");

		XmlSubXCV result = new XmlSubXCV();
		SurnameCheck sc = new SurnameCheck(result, new CertificateWrapper(xc), constraint);
		sc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedSurnameCheck() throws Exception {
		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Invalid_Surname");

		XmlCertificate xc = new XmlCertificate();
		xc.setSurname("Valid_Surname");

		XmlSubXCV result = new XmlSubXCV();
		SurnameCheck sc = new SurnameCheck(result, new CertificateWrapper(xc), constraint);
		sc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
