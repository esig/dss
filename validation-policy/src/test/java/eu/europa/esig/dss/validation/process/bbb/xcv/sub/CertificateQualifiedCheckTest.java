package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.QCStatementOids;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateQualifiedCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateQualifiedCheckTest {

	@Test
	public void certificateQualifiedCheckWithQCStatement() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xc = new XmlCertificate();

		List<XmlOID> qcStatementIds = new ArrayList<XmlOID>();
		XmlOID oid = new XmlOID();
		oid.setValue(QCStatementOids.QC_COMPLIANT.getOid());
		qcStatementIds.add(oid);
		xc.setQCStatementIds(qcStatementIds);

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cqc = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cqc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void certificateQualifiedCheckWithCertificate() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xc = new XmlCertificate();
		List<XmlOID> certPolicies = new ArrayList<XmlOID>();
		XmlOID oid = new XmlOID();
		oid.setValue(CertificatePolicyOids.QCP_PUBLIC.getOid());
		certPolicies.add(oid);
		xc.setCertificatePolicyIds(certPolicies);

		XmlSubXCV result = new XmlSubXCV();
		CertificateQualifiedCheck cqc = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cqc.execute();

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
		CertificateQualifiedCheck cqc = new CertificateQualifiedCheck(result, new CertificateWrapper(xc), constraint);
		cqc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
