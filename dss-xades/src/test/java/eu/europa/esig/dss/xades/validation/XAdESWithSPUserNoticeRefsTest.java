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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XAdESWithSPUserNoticeRefsTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-with-spUserNotice-refs.xml");
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setDataLoader(new IgnoreDataLoader());
        return signaturePolicyProvider;
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals("1.2.3.4.5.6", signature.getPolicyId());
        assertEquals("Test description", signature.getPolicyDescription());
        assertEquals(2, signature.getPolicyDocumentationReferences().size());
        assertEquals("http://spuri.test", signature.getPolicyUrl());
        assertNotNull(signature.getPolicyUserNotice());
        assertEquals("Nowina", signature.getPolicyUserNotice().getOrganization());
        assertEquals(DSSUtils.toBigIntegerList(new int[] {1, 2, 3}), signature.getPolicyUserNotice().getNoticeNumbers());
    }

}
