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
package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class ContentHintsCheckTest {

	@Test
	public void contentHintsCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setContentHints("Valid_Value");

		ValueConstraint constraint = new ValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue("Valid_Value");

		XmlSAV result = new XmlSAV();
		ContentHintsCheck chc = new ContentHintsCheck(result, new SignatureWrapper(sig), constraint);
		chc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedContentHintsCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		sig.setContentHints("Invalid_Value");

		ValueConstraint constraint = new ValueConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.setValue("Valid_Value");

		XmlSAV result = new XmlSAV();
		ContentHintsCheck chc = new ContentHintsCheck(result, new SignatureWrapper(sig), constraint);
		chc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
