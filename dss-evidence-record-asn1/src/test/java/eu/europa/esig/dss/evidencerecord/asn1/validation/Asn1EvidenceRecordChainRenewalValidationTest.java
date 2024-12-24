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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.List;

class Asn1EvidenceRecordChainRenewalValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/ER-2Chains3ATS.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Arrays.asList(new InMemoryDocument("content of data object DO-01".getBytes(), "ER-2Chains3ATS1.bin"),
    						 new InMemoryDocument("content of data object DO-02".getBytes(), "ER-2Chains3ATS2.bin"));
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        // second tst covers other data too
        return false;
    }

}
