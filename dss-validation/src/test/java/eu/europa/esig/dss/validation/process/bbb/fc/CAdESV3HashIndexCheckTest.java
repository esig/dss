/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlArchiveTimestampHashIndex;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.CAdESV3HashIndexCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CAdESV3HashIndexCheckTest extends AbstractTestCheck {

    @Test
    void valid() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setValid(true);
        xmlTimestamp.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalid() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setValid(false);
        xmlTimestamp.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void noAtsHashIndex() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void cadesV2Tst() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
        xmlTimestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_V2);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void sigTstTst() {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();

        xmlTimestamp.setType(TimestampType.SIGNATURE_TIMESTAMP);

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);

        XmlFC result = new XmlFC();
        CAdESV3HashIndexCheck chic = new CAdESV3HashIndexCheck(i18nProvider, result, new TimestampWrapper(xmlTimestamp), new LevelConstraintWrapper(constraint));
        chic.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
