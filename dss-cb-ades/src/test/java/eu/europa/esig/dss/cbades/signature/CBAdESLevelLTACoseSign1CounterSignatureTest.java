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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelLTACoseSign1CounterSignatureTest extends AbstractCBAdESCounterSignatureTest {

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;
    private CBAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new InMemoryDocument("Hello world!".getBytes(), "HelloWorld");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LTA);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        counterSignatureParameters = new CBAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LTA);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        CBORValue coseSign1 = CBORUtils.parseCbor(byteArray);
        assertNotNull(coseSign1);
        assertTrue(coseSign1.isTag());

        coseSign1 = coseSign1.getTaggedValue();
        assertNotNull(coseSign1);
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
        int counterSigCounter = 0;

        for (CBORValue uHeadersComponent : uHeaders.getElements()) {
            assertTrue(uHeadersComponent.isByteString()); // cbor btsr encoded

            CBORValue uHeaderObject = CBORUtils.parseCbor(uHeadersComponent.asBytes());
            assertNotNull(uHeaderObject);
            assertTrue(uHeaderObject.isMap());

            assertEquals(1, uHeaderObject.size());

            CBORValue sigTst = uHeaderObject.get(COSEHeaderParameter.SIG_TST.cbor());
            if (sigTst != null) {
                ++sigTstCounter;

                CBORValue tstTokens = sigTst.getAsArrayOrNull(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
                assertNotNull(tstTokens);
                assertEquals(1, tstTokens.size());
            }
            CBORValue valData = uHeaderObject.get(COSEHeaderParameter.VAL_DATA.cbor());
            if (valData != null) {
                ++valDataCounter;
            }
            CBORValue arcTst = uHeaderObject.get(COSEHeaderParameter.ARC_TST.cbor());
            if (arcTst != null) {
                ++arcTstCounter;

                CBORValue tstTokens = arcTst.getAsArrayOrNull(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
                assertNotNull(tstTokens);
                assertEquals(1, tstTokens.size());
            }
            CBORValue counterSig = uHeaderObject.get(COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor());
            if (counterSig != null) {
                ++counterSigCounter;

                assertFalse(counterSig.isTag());
                assertTrue(counterSig.isArray());

                assertEquals(3, counterSig.size());
            }
        }

        assertEquals(1, sigTstCounter);
        assertEquals(1, valDataCounter);
        assertEquals(1, arcTstCounter);
        assertEquals(1, counterSigCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.CB_AdES_BASELINE_LTA, signatureWrapper.getSignatureFormat());
        }
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(4, diagnosticData.getTimestampList().size());

        int sigTstCounter = 0;
        int arcTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertEquals(1, timestampWrapper.getTimestampedSignatures().size());

            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++sigTstCounter;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++arcTstCounter;
            }
        }
        assertEquals(2, sigTstCounter);
        assertEquals(2, arcTstCounter);
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CBAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
