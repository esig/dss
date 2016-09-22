package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheckWithNullConstraint;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataFreshCheckWithNullConstraintTest {

	@Test
	public void revocationDataFreshCheckWithNullConstraint() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 129600000)); // 36 hours ago
		xr.setNextUpdate(new Date(nowMil - 43200000)); // 12 hours ago -> max
														// freshness is 24 hours
		xr.setProductionDate(new Date(nowMil - 72000000)); // 20 hours ago ->
															// fresh

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheckWithNullConstraint rdfwncc = new RevocationDataFreshCheckWithNullConstraint(result,
				new RevocationWrapper(xr), now, constraint);
		rdfwncc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedRevocationDataFreshCheckWithNullConstraint() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 129600000)); // 36 hours ago
		xr.setNextUpdate(new Date(nowMil - 43200000)); // 12 hours ago -> max
														// freshness is 24 hours
		xr.setProductionDate(new Date(nowMil - 144000000)); // 20 hours ago ->
															// not fresh

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheckWithNullConstraint rdfwncc = new RevocationDataFreshCheckWithNullConstraint(result,
				new RevocationWrapper(xr), now, constraint);
		rdfwncc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
