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
package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.jose4j.json.JsonUtil;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESExtensionLTToLTUpdateTest extends AbstractJAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LT;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LT;
    }

    @Override
    protected JAdESService getSignatureServiceToSign() {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(null);
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        JAdESService service = new JAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtSignatureTime());
        return service;
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        // no complete revocation data
        assertEquals(SignatureLevel.JAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DSSDocument extendedDocument = super.extendSignature(signedDocument);

        assertTrue(DSSJsonUtils.isJsonDocument(extendedDocument));
        Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(extendedDocument)));

        Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get(JWSConstants.HEADER);
        assertTrue(Utils.isMapNotEmpty(unprotected));

        List<Object> unsignedProperties = (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);

        boolean xValsFound = false;
        boolean rValsFound = false;

        boolean crlValsFound = false;
        boolean ocspValsFound = false;

        for (Object property : unsignedProperties) {
            Map<?, ?> map = DSSJsonUtils.parseEtsiUComponent(property);
            List<?> xVals = (List<?>) map.get(JAdESHeaderParameterNames.X_VALS);
            if (xVals != null) {
                assertFalse(xValsFound);
                xValsFound = true;
            }
            Map<?, ?> rVals = (Map<?, ?>) map.get(JAdESHeaderParameterNames.R_VALS);
            if (rVals != null) {
                assertFalse(rValsFound);
                rValsFound = true;

                List<?> crlVals = (List<?>) rVals.get(JAdESHeaderParameterNames.CRL_VALS);
                if (Utils.isCollectionNotEmpty(crlVals)) {
                    crlValsFound = true;
                }

                List<?> ocspVals = (List<?>) rVals.get(JAdESHeaderParameterNames.OCSP_VALS);
                if (Utils.isCollectionNotEmpty(ocspVals)) {
                    ocspValsFound = true;
                }
            }
        }

        assertTrue(xValsFound);
        assertTrue(rValsFound);
        assertTrue(crlValsFound);
        assertTrue(ocspValsFound);

        return extendedDocument;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_WITH_CRL_AND_OCSP;
    }

}
