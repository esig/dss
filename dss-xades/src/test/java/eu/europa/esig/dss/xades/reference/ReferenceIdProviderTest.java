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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReferenceIdProviderTest {

    @Test
    public void defaultTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        assertEquals("r-1", referenceIdProvider.getReferenceId());
        assertEquals("r-2", referenceIdProvider.getReferenceId());
        assertEquals("r-3", referenceIdProvider.getReferenceId());
        assertEquals("r-4", referenceIdProvider.getReferenceId());
        assertEquals("r-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        assertEquals("r-1", referenceIdProvider.getReferenceId());
        assertEquals("r-2", referenceIdProvider.getReferenceId());
        assertEquals("r-3", referenceIdProvider.getReferenceId());
        assertEquals("r-4", referenceIdProvider.getReferenceId());
        assertEquals("r-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void customPrefixTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void signatureParamsTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());
    }

    @Test
    public void combinationParamsTest() {
        ReferenceIdProvider referenceIdProvider = new ReferenceIdProvider();
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());

        referenceIdProvider = new ReferenceIdProvider();
        signatureParameters = new XAdESSignatureParameters();
        referenceIdProvider.setSignatureParameters(signatureParameters);
        referenceIdProvider.setReferenceIdPrefix("r-manifest");
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-1", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-2", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-3", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-4", referenceIdProvider.getReferenceId());
        assertEquals("r-manifest-" + signatureParameters.getDeterministicId() + "-5", referenceIdProvider.getReferenceId());
    }

}
