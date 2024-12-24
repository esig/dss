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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Arrays;
import java.util.List;

class Asn1EvidenceRecordTstRenewalValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-tst-renewal.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "nOLX01D5QYQHQ58MoR3MEquffNsV+ezF7Kk1SCYCuHI=", "doc1"),
                new DigestDocument(DigestAlgorithm.SHA256, "7sxNM1LA6WX9iHle39GmDFrAmzwRAMBS67auC9NDKyY=", "doc2")
        );
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        return false;
    }

}
