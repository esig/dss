package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class CommitmentTypeIndicationsCheckTest {

	@Test
	public void commitmentTypeIndicationsCheck() throws Exception {
		List<String> commitmentTypeIndication = new ArrayList<String>();
		commitmentTypeIndication.add("1");
		commitmentTypeIndication.add("2");

		XmlSignature sig = new XmlSignature();
		sig.setCommitmentTypeIndication(commitmentTypeIndication);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1");
		constraint.getId().add("2");
		constraint.getId().add("3");

		XmlSAV result = new XmlSAV();
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(result, new SignatureWrapper(sig),
				constraint);
		ctic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCommitmentTypeIndicationsCheck() throws Exception {
		List<String> commitmentTypeIndication = new ArrayList<String>();
		commitmentTypeIndication.add("1");
		commitmentTypeIndication.add("4");

		XmlSignature sig = new XmlSignature();
		sig.setCommitmentTypeIndication(commitmentTypeIndication);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1");
		constraint.getId().add("2");
		constraint.getId().add("3");

		XmlSAV result = new XmlSAV();
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(result, new SignatureWrapper(sig),
				constraint);
		ctic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void emptyListCommitmentTypeIndicationsCheck() throws Exception {
		XmlSignature sig = new XmlSignature();

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1");
		constraint.getId().add("2");
		constraint.getId().add("3");

		XmlSAV result = new XmlSAV();
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(result, new SignatureWrapper(sig),
				constraint);
		ctic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
