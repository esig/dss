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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;

import java.util.ArrayList;
import java.util.List;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeout;

// For manual testing (too many entries for some environments)
@Tag("slow")
@Disabled
class XAdESTooManyDataObjectFormatValidationTest extends AbstractXAdESTestValidation {
    
    private static final List<DSSDocument> DETACHED_DOCUMENTS = new ArrayList<>();

    static {
        for (int i = 1; i <= 900; i++) {
            DETACHED_DOCUMENTS.add(new InMemoryDocument(String.format("test content %s", i).getBytes(), String.format("testFile_%s.txt", i)));
        }
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-900-references.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return DETACHED_DOCUMENTS;
    }

    @Override
    protected Reports validateDocument(DocumentValidator validator) {
        Reports reports = super.validateDocument(validator);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        assertTimeout(ofMillis(15000), () -> signatures.get(0).getDataFoundUpToLevel());

        return reports;
    }

    /**
     * For manual testing
     */
    @Disabled
    @Override
    public void validate() {
        super.validate();
    }

}
