package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevokedCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateRevokedCheckTest {

	@Test
	public void certificateRevokedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		xr.setStatus(false);
		xr.setReason("certificateHold");

		XmlCertificate xc = new XmlCertificate();
		xc.getRevocations().add(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateRevokedCheck cec = new CertificateRevokedCheck(result, new CertificateWrapper(xc), constraint, SubContext.CA_CERTIFICATE);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateRevokedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		xr.setStatus(false);
		xr.setReason("certificate");

		XmlCertificate xc = new XmlCertificate();
		xc.getRevocations().add(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateRevokedCheck cec = new CertificateRevokedCheck(result, new CertificateWrapper(xc), constraint, SubContext.CA_CERTIFICATE);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
