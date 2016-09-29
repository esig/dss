package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateSignatureValidCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateSignatureValidCheckTest {

	@Test
	public void certificateSignatureValidCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlBasicSignature xbs = new XmlBasicSignature();
		xbs.setSignatureValid(true);
		XmlCertificate xc = new XmlCertificate();
		xc.setBasicSignature(xbs);

		XmlSubXCV result = new XmlSubXCV();
		CertificateSignatureValidCheck<XmlSubXCV> csvc = new CertificateSignatureValidCheck<XmlSubXCV>(result,
				new CertificateWrapper(xc), constraint);
		csvc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateSignatureValidCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlBasicSignature xbs = new XmlBasicSignature();
		xbs.setSignatureValid(false);
		XmlCertificate xc = new XmlCertificate();
		xc.setBasicSignature(xbs);

		XmlSubXCV result = new XmlSubXCV();
		CertificateSignatureValidCheck<XmlSubXCV> csvc = new CertificateSignatureValidCheck<XmlSubXCV>(result,
				new CertificateWrapper(xc), constraint);
		csvc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
