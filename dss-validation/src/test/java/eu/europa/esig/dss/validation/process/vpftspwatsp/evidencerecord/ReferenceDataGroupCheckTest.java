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
package eu.europa.esig.dss.validation.process.vpftspwatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataGroupCheck;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReferenceDataGroupCheckTest extends AbstractTestCheck {

    @Test
    void validCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void oneInvalidRefCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noneValidRefsCheck() {
        XmlDigestMatcher oneDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        XmlDigestMatcher twoDigestMatcher = new XmlDigestMatcher();
        oneDigestMatcher.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);

        List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
        digestMatchers.add(oneDigestMatcher);
        digestMatchers.add(twoDigestMatcher);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlCV result = new XmlCV();
        ReferenceDataGroupCheck<XmlCV> rdgc = new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
        rdgc.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

}
