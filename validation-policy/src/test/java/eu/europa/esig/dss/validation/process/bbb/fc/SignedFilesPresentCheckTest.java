package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedFilesPresentCheck;

public class SignedFilesPresentCheckTest extends AbstractTestCheck {

	@Test
	public void asicsValidTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("package.zip"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicsNoFileTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicsMultipleFilesTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello.xml", "world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asicsNotRootFileTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_S);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asiceValidTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello.xml", "world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asiceOneFileTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("package.zip"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void asiceNoFileTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void asiceNotRootFileTest() throws Exception {
		XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
		xmlContainerInfo.setContainerType(ASiCContainerType.ASiC_E);
		xmlContainerInfo.setContentFiles(Arrays.asList("hello/world.xml"));

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		SignedFilesPresentCheck sfpc = new SignedFilesPresentCheck(i18nProvider, result, xmlContainerInfo, constraint);
		sfpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

}
