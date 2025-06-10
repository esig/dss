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
package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESExtensionTToLTANotTrustedTSPTest extends AbstractJAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LTA;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getSHA3GoodTsa();
    }

    @Override
    protected JAdESService getSignatureServiceToExtend() {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.importAsTrusted(getGoodPKITrustAnchors());
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);

        JAdESService service = new JAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());

        return service;
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, super::extendAndVerify);
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));
        assertTrue(exception.getMessage().contains("Revocation data is skipped for untrusted certificate chain!"));
    }

}
