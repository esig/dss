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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionBToTWithRevokedCertTest extends AbstractXAdESTestExtension {

    private XAdESSignatureParameters signatureParameters;
    private XAdESSignatureParameters extensionParameters;

    @BeforeEach
    void init() {
        signatureParameters = super.getSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(false);

        extensionParameters = super.getExtensionParameters();
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected XAdESSignatureParameters getExtensionParameters() {
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        extensionParameters.setCheckCertificateRevocation(true);
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        extensionParameters.setCheckCertificateRevocation(false);
        return super.extendSignature(signedDocument);
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}
