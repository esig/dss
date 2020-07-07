/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
