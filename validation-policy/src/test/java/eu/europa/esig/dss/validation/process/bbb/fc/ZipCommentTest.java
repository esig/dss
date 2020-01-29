package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableZipCommentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ZipCommentPresentCheck;

public class ZipCommentTest extends AbstractTestCheck {

	@Test
	public void zipCommentFail() throws Exception {

		String zipComment = "";

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ZipCommentPresentCheck fc = new ZipCommentPresentCheck(i18nProvider, result, zipComment, constraint);
		fc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		MultiValuesConstraint multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);

		AcceptableZipCommentCheck acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);
		multiValue.getId().add("*");

		acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void zipCommentOk() throws Exception {
		String zipComment = "ok";

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ZipCommentPresentCheck fc = new ZipCommentPresentCheck(i18nProvider, result, zipComment, constraint);
		fc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		MultiValuesConstraint multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);

		AcceptableZipCommentCheck acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);
		multiValue.getId().add("*");

		acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);
		multiValue.getId().add("ko");

		acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());

		// -------------------------------------------
		result = new XmlFC();
		multiValue = new MultiValuesConstraint();
		multiValue.setLevel(Level.FAIL);
		multiValue.getId().add("ok");

		acceptable = new AcceptableZipCommentCheck(i18nProvider, result, zipComment, multiValue);
		acceptable.execute();

		constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

}
