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
package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ManifestEntryExistenceCheck;

class ManifestEntryExistenceCheckTest extends AbstractTestCheck {

	@Test
	void valid() throws Exception {
		XmlDigestMatcher manifest = new XmlDigestMatcher();
		manifest.setType(DigestMatcherType.MANIFEST);
		
		XmlDigestMatcher entry1 = new XmlDigestMatcher();
		entry1.setType(DigestMatcherType.MANIFEST_ENTRY);
		
		XmlDigestMatcher entry2 = new XmlDigestMatcher();
		entry2.setType(DigestMatcherType.MANIFEST_ENTRY);
		
		List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ManifestEntryExistenceCheck meec = new ManifestEntryExistenceCheck(i18nProvider, result, digestMatchers, constraint);
		meec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void invalid() throws Exception {
		XmlDigestMatcher manifest = new XmlDigestMatcher();
		manifest.setType(DigestMatcherType.MANIFEST);
		
		XmlDigestMatcher entry1 = new XmlDigestMatcher();
		entry1.setType(DigestMatcherType.OBJECT);
		
		XmlDigestMatcher entry2 = new XmlDigestMatcher();
		entry2.setType(DigestMatcherType.KEY_INFO);
		
		List<XmlDigestMatcher> digestMatchers = Arrays.asList(manifest, entry1, entry2);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCV result = new XmlCV();
		ManifestEntryExistenceCheck meec = new ManifestEntryExistenceCheck(i18nProvider, result, digestMatchers, constraint);
		meec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
