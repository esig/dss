package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQualifiedCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateQualifiedCheckTest {

	@Test
	public void certificateQualifiedCheckWithQCStatement() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		List<String> qcStatementIds = new ArrayList<String>();
		qcStatementIds.add(QCStatementPolicyIdentifiers.QC_COMPLIANT);

		XmlCertificate xc = new XmlCertificate();
		xc.setQCStatementIds(qcStatementIds);

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cec = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void certificateQualifiedCheckWithCertificate() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xc = new XmlCertificate();
		xc.getCertificatePolicyIds().add(CertificatePolicyIdentifiers.QCP_PUBLIC);

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cec = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void certificateQualifiedCheckWithCertificateTSP() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		List<String> qualifiers = new ArrayList<String>();
		qualifiers.add("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement");

		XmlTrustedServiceProvider xtsp = new XmlTrustedServiceProvider();
		xtsp.setQualifiers(qualifiers);

		XmlCertificate xc = new XmlCertificate();
		xc.getTrustedServiceProvider().add(xtsp);

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cec = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateQualifiedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xc = new XmlCertificate();

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cec = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
