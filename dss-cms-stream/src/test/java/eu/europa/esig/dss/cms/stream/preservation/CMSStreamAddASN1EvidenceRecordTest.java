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
package eu.europa.esig.dss.cms.stream.preservation;

import eu.europa.esig.dss.cades.preservation.AbstractCAdESAddEvidenceRecordTest;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CMSStreamAddASN1EvidenceRecordTest extends AbstractCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CMSStreamAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CMSStreamAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.ers"));
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return null;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(UnsupportedOperationException.class, super::addERAndValidate);
        assertEquals("Embedding of Evidence Record is not supported by the dss-cms-stream implementation! " +
                "Please switch to 'dss-cms-object' if support is required.", exception.getMessage());
    }

}