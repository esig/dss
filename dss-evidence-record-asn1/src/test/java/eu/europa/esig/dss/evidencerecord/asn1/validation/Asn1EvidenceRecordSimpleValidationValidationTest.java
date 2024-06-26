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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Asn1EvidenceRecordSimpleValidationValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/BIN-1_ER.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "odTntQ2Wk/mjGy6UhOpq36WFg3cw/iupTROl1MgcMt8=", "some binary content"),
                new DigestDocument(DigestAlgorithm.SHA256, "2Eg+KWYIINZGWWKP1rUlW4zrtlKk5Ws2VEVJA6fSSgQ=", "some binary content two")
        );
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(2, evidenceRecordScopes.size());

        for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
            assertNotNull(signatureScope.getSignerData());
            assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
            assertNotNull(signatureScope.getName());
            assertEquals("Full document", signatureScope.getDescription());
        }
    }

}
