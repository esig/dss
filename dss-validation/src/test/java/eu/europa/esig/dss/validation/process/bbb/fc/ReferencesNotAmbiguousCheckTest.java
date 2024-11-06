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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ReferencesNotAmbiguousCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReferencesNotAmbiguousCheckTest extends AbstractTestCheck {

	@Test
	void valid() {
		XmlSignature sig = new XmlSignature();

		XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
		xmlDigestMatcher.setType(DigestMatcherType.REFERENCE);
		xmlDigestMatcher.setDuplicated(false);

		sig.getDigestMatchers().add(xmlDigestMatcher);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ReferencesNotAmbiguousCheck rnac = new ReferencesNotAmbiguousCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);
		rnac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void fail() {
		XmlSignature sig = new XmlSignature();

		XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
		xmlDigestMatcher.setType(DigestMatcherType.REFERENCE);
		xmlDigestMatcher.setDuplicated(true);

		sig.getDigestMatchers().add(xmlDigestMatcher);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		ReferencesNotAmbiguousCheck rnac = new ReferencesNotAmbiguousCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);
		rnac.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
