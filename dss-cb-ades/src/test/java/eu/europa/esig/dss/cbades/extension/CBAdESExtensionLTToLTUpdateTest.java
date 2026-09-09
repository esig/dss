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
package eu.europa.esig.dss.cbades.extension;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESExtensionLTToLTUpdateTest extends AbstractCBAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CB_AdES_BASELINE_LT;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CB_AdES_BASELINE_LT;
    }

    @Override
    protected CBAdESService getSignatureServiceToSign() {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(null);
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        CBAdESService service = new CBAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtSignatureTime());
        return service;
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        // no complete revocation data
        assertEquals(SignatureLevel.CB_AdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        DSSDocument extendedDocument = super.extendSignature(signedDocument);
        assertTrue(CBORUtils.isCbor(extendedDocument));

        byte[] binaries = DSSUtils.toByteArray(extendedDocument);
        CBORValue coseSign1 = CBORUtils.parseCbor(binaries);
        assertNotNull(coseSign1);
        assertTrue(coseSign1.isTag());
        coseSign1 = coseSign1.getTaggedValue();
        assertTrue(coseSign1.isArray());

        assertEquals(4, coseSign1.size());

        CBORValue protectedHeader = coseSign1.get(0);
        assertTrue(protectedHeader.isByteString());

        CBORValue parsedProtectedHeader = CBORUtils.parseCbor(protectedHeader.asBytes());
        assertNotNull(parsedProtectedHeader);
        assertTrue(parsedProtectedHeader.isMap());
        assertTrue(parsedProtectedHeader.size() > 0);

        CBORValue unprotectedHeader = coseSign1.get(1);
        assertTrue(unprotectedHeader.isMap());

        assertEquals(1, unprotectedHeader.size());

        CBORValue uHeaders = unprotectedHeader.get(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertTrue(uHeaders.isArray());

        assertTrue(uHeaders.size() > 0);

        int sigTstCounter = 0;
        int valDataCounter = 0;
        int arcTstCounter = 0;

        boolean xValsFound = false;
        boolean rValsFound = false;

        boolean crlValsFound = false;
        boolean ocspValsFound = false;

        for (CBORValue uHeadersComponent : uHeaders.getElements()) {
            assertTrue(uHeadersComponent.isByteString()); // cbor btsr encoded

            CBORValue uHeaderObject = CBORUtils.parseCbor(uHeadersComponent.asBytes());
            assertNotNull(uHeaderObject);
            assertTrue(uHeaderObject.isMap());

            assertEquals(1, uHeaderObject.size());

            CBORValue sigTst  = uHeaderObject.get(COSEHeaderParameter.SIG_TST.cbor());
            if (sigTst != null) {
                ++sigTstCounter;

                CBORValue tstTokens = sigTst.getAsArrayOrNull(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
                assertEquals(1, tstTokens.size());
            }
            CBORValue valData  = uHeaderObject.get(COSEHeaderParameter.VAL_DATA.cbor());
            if (valData != null) {
                if (valData.getAsArrayOrNull(COSEHeaderParameter.VAL_DATA_X_VALS.cbor()) != null) {
                    xValsFound = true;
                }
                CBORValue rVals = valData.getAsMapOrNull(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
                assertNotNull(rVals);
                rValsFound = true;

                if (rVals.getAsArrayOrNull(COSEHeaderParameter.R_VALS_CRL_VALS.cbor()) != null) {
                    crlValsFound = true;
                }
                if (rVals.getAsArrayOrNull(COSEHeaderParameter.R_VALS_OCSP_VALS.cbor()) != null) {
                    ocspValsFound = true;
                }

                ++valDataCounter;
            }
            CBORValue arcTst  = uHeaderObject.get(COSEHeaderParameter.ARC_TST.cbor());
            if (arcTst != null) {
                ++arcTstCounter;
            }
        }

        assertEquals(1, sigTstCounter);
        assertEquals(1, valDataCounter);
        assertEquals(0, arcTstCounter);

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
