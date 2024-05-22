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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;

public class CommitmentTypeIndicationsCheckTest extends AbstractTestCheck {

	@Test
	public void commitmentTypeIndicationsCheck() throws Exception {
		List<XmlCommitmentTypeIndication> commitmentTypeIndications = new ArrayList<>();
		XmlCommitmentTypeIndication commitmentTypeIndication1 = new XmlCommitmentTypeIndication();
		commitmentTypeIndication1.setIdentifier("1");
		commitmentTypeIndications.add(commitmentTypeIndication1);
		XmlCommitmentTypeIndication commitmentTypeIndication2 = new XmlCommitmentTypeIndication();
		commitmentTypeIndication2.setIdentifier("2");
		commitmentTypeIndications.add(commitmentTypeIndication2);

		XmlSignature sig = new XmlSignature();
		sig.getCommitmentTypeIndications().addAll(commitmentTypeIndications);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1");
		constraint.getId().add("2");
		constraint.getId().add("3");

		XmlSAV result = new XmlSAV();
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(i18nProvider, result, new SignatureWrapper(sig),
				constraint);
		ctic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCommitmentTypeIndicationsCheck() throws Exception {
		List<XmlCommitmentTypeIndication> commitmentTypeIndications = new ArrayList<>();
		XmlCommitmentTypeIndication commitmentTypeIndication1 = new XmlCommitmentTypeIndication();
		commitmentTypeIndication1.setIdentifier("1");
		commitmentTypeIndications.add(commitmentTypeIndication1);
		XmlCommitmentTypeIndication commitmentTypeIndication4 = new XmlCommitmentTypeIndication();
		commitmentTypeIndication4.setIdentifier("4");
		commitmentTypeIndications.add(commitmentTypeIndication4);

		XmlSignature sig = new XmlSignature();
		sig.getCommitmentTypeIndications().addAll(commitmentTypeIndications);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1");
		constraint.getId().add("2");
		constraint.getId().add("3");

		XmlSAV result = new XmlSAV();
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(i18nProvider, result, new SignatureWrapper(sig),
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
		CommitmentTypeIndicationsCheck ctic = new CommitmentTypeIndicationsCheck(i18nProvider, result, new SignatureWrapper(sig),
				constraint);
		ctic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
