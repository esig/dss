package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateExpirationCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateExpirationCheckTest {

	@Test
	public void certificateExpirationCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		Date now = new Date();
		long nowMil = now.getTime();
		XmlCertificate xc = new XmlCertificate();
		xc.setNotAfter(new Date(nowMil + 86400000)); // in 24 hours
		xc.setNotBefore(new Date(nowMil - 86400000)); // 24 hours ago

		XmlSubXCV result = new XmlSubXCV();
		CertificateExpirationCheck cec = new CertificateExpirationCheck(result, new CertificateWrapper(xc), new Date(),
				constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateExpirationCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		Date now = new Date();
		long nowMil = now.getTime();
		XmlCertificate xc = new XmlCertificate();
		xc.setNotAfter(new Date(nowMil - 86400000)); // 24 hours ago
		xc.setNotBefore(new Date(nowMil - 172800000)); // 48 hours ago

		XmlSubXCV result = new XmlSubXCV();
		CertificateExpirationCheck cec = new CertificateExpirationCheck(result, new CertificateWrapper(xc), new Date(),
				constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
