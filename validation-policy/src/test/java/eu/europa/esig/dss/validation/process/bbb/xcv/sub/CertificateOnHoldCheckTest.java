package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.Calendar;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateOnHoldCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateOnHoldCheckTest {

	private static final Calendar CAL1 = DatatypeConverter.parseDate("2017-01-01");
	private static final Calendar CAL2 = DatatypeConverter.parseDate("2018-01-01");

	@Test
	public void certificateOnHoldCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		xr.setStatus(true);

		XmlCertificate xc = new XmlCertificate();
		xc.getRevocations().add(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateOnHoldCheck cohc = new CertificateOnHoldCheck(result, new CertificateWrapper(xc), CAL2.getTime(), constraint);
		cohc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateOnHoldCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		xr.setStatus(false);
		xr.setRevocationDate(CAL1.getTime());
		xr.setReason("certificateHold");

		XmlCertificate xc = new XmlCertificate();
		xc.getRevocations().add(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateOnHoldCheck cohc = new CertificateOnHoldCheck(result, new CertificateWrapper(xc), CAL2.getTime(), constraint);
		cohc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
