package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TimestampMessageImprintDataIntactCheck;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampMessageImprintDataIntactCheckTest {

	@Test
	public void TimestampMessageImprintDataIntactCheck() throws Exception {
		XmlTimestamp xts = new XmlTimestamp();
		xts.setMessageImprintDataIntact(true);
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		TimestampMessageImprintDataIntactCheck tmpdic = new TimestampMessageImprintDataIntactCheck(result,
				new TimestampWrapper(xts), constraint);
		tmpdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

	}

	@Test
	public void failedTimestampMessageImprintDataIntactCheck() throws Exception {
		XmlTimestamp xts = new XmlTimestamp();
		xts.setMessageImprintDataIntact(false);
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlSAV result = new XmlSAV();
		TimestampMessageImprintDataIntactCheck tmpdic = new TimestampMessageImprintDataIntactCheck(result,
				new TimestampWrapper(xts), constraint);
		tmpdic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
