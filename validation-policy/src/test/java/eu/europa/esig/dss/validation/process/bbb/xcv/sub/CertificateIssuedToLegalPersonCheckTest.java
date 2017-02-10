package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateIssuedToLegalPersonCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateIssuedToLegalPersonCheckTest {

	@Test
	public void certificateIssuedToLegalPersonWithPolicyIdentifierCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		List<XmlOID> qualifiers = new ArrayList<XmlOID>();
		XmlOID oid = new XmlOID();
		oid.setValue(CertificatePolicyOids.QCP_LEGAL.getOid());
		qualifiers.add(oid);

		XmlCertificate xc = new XmlCertificate();
		xc.setCertificatePolicyIds(qualifiers);

		XmlSubXCV result = new XmlSubXCV();
		CertificateIssuedToLegalPersonCheck citlp = new CertificateIssuedToLegalPersonCheck(result, new CertificateWrapper(xc), constraint);
		citlp.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateIssuedToLegalPersonWithPolicyIdentifierCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		List<XmlOID> qualifiers = new ArrayList<XmlOID>();
		XmlOID oid = new XmlOID();
		oid.setValue(CertificatePolicyOids.QCP_NATURAL.getOid());
		qualifiers.add(oid);

		XmlCertificate xc = new XmlCertificate();
		xc.setCertificatePolicyIds(qualifiers);

		XmlSubXCV result = new XmlSubXCV();
		CertificateIssuedToLegalPersonCheck citlp = new CertificateIssuedToLegalPersonCheck(result, new CertificateWrapper(xc), constraint);
		citlp.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
