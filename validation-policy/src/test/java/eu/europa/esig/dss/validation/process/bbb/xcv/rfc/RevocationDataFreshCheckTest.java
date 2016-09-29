package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheck;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.TimeUnit;

public class RevocationDataFreshCheckTest {

	@Test
	public void revocationDataFreshCheck() throws Exception {
		TimeConstraint tc = new TimeConstraint();
		tc.setUnit(TimeUnit.DAYS);
		tc.setValue(1);
		tc.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setProductionDate(new Date(nowMil - 43200000)); // 12 hours ago

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheck rdec = new RevocationDataFreshCheck(result, new RevocationWrapper(xr), now, tc);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedRevocationDataFreshCheck() throws Exception {
		TimeConstraint tc = new TimeConstraint();
		tc.setUnit(TimeUnit.DAYS);
		tc.setValue(1);
		tc.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setProductionDate(new Date(nowMil - 172800000)); // 48 hours ago

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheck rdec = new RevocationDataFreshCheck(result, new RevocationWrapper(xr), now, tc);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
