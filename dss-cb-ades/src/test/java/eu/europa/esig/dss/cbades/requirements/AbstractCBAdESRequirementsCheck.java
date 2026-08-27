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
package eu.europa.esig.dss.cbades.requirements;

import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.AbstractCBAdESTestSignature;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCBAdESRequirementsCheck extends AbstractCBAdESTestSignature {

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new InMemoryDocument("Hello world!".getBytes(), "doc.txt");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray)  {
        super.onDocumentSigned(byteArray);

        try {
            CBORByteString payload = getPayload(byteArray);
            checkPayload(payload);

            CBORByteString protectedHeader = getProtectedHeader(byteArray);
            checkProtectedHeader(protectedHeader);

            CBORByteString signatureValue = getSignatureValue(byteArray);
            checkSignatureValue(signatureValue);

            CBORMap unprotectedHeader = getUnprotectedHeader(byteArray);
            checkUnprotectedHeader(unprotectedHeader);

        } catch (Exception e) {
            fail(e);
        }
    }

    protected abstract CBORByteString getPayload(byte[] byteArray) throws Exception;

    protected abstract CBORByteString getProtectedHeader(byte[] byteArray) throws Exception;

    protected abstract CBORByteString getSignatureValue(byte[] byteArray) throws Exception;

    protected abstract CBORMap getUnprotectedHeader(byte[] byteArray) throws Exception;

    protected void checkPayload(CBORByteString payload) {
        assertNotNull(payload);
        assertTrue(Utils.isArrayNotEmpty(payload.getValueAsBytes()));
    }

    protected void checkProtectedHeader(CBORByteString protectedHeader) {
        assertNotNull(protectedHeader);
        assertTrue(Utils.isArrayNotEmpty(protectedHeader.getValueAsBytes()));

        CBORObject protectedHeaderObject = CBORUtils.parseCbor(protectedHeader.getValueAsBytes());
        assertTrue(protectedHeaderObject.isMap());

        CBORMap protectedHeaderMap = (CBORMap) protectedHeaderObject;
        assertFalse(protectedHeaderMap.isEmpty());

        checkSigningCertificate(protectedHeaderMap);
        checkCertificateChain(protectedHeaderMap);
        checkSigningTime(protectedHeaderMap);
        checkContentType(protectedHeaderMap);
        checkCrit(protectedHeaderMap);
    }

    protected void checkSigningCertificate(CBORMap protectedHeaderMap) {
        CBORArray x5t = protectedHeaderMap.getAsArray(CBORObjectFactory.toCBORObject(34L));
        CBORArray x5ts = protectedHeaderMap.getAsArray(CBORObjectFactory.toCBORObject(261L));
        assertTrue(x5t != null ^ x5ts != null);

        if (x5t != null) {
            Long hashAlg = x5t.getAsLong(0);
            assertNotNull(hashAlg);
            assertNotNull(DigestAlgorithm.forCOSE(hashAlg));

            byte[] hashVal = x5t.getAsBinaries(1);
            assertNotNull(hashVal);
            assertTrue(Utils.isArrayNotEmpty(hashVal));
        }

        if (x5ts != null) {
            assertFalse(x5ts.isEmpty());

            for (CBORObject cborObject : x5ts.getValueAsList()) {
                assertTrue(cborObject.isArray());
                CBORArray x5tItem = (CBORArray) cborObject;

                Long hashAlg = x5tItem.getAsLong(0);
                assertNotNull(hashAlg);
                assertNotNull(DigestAlgorithm.forCOSE(hashAlg));

                byte[] hashVal = x5tItem.getAsBinaries(1);
                assertNotNull(hashVal);
                assertTrue(Utils.isArrayNotEmpty(hashVal));
            }
        }
    }

    private void checkCertificateChain(CBORMap protectedHeaderMap) {
        CBORArray x5chain = protectedHeaderMap.getAsArray(CBORObjectFactory.toCBORObject(33L));
        assertNotNull(x5chain);
        assertFalse(x5chain.isEmpty());
        for (CBORObject certObject : x5chain.getValueAsList()) {
            assertNotNull(certObject);
            assertTrue(certObject.isByteString());

            CBORByteString cert = (CBORByteString) certObject;
            assertTrue(Utils.isArrayNotEmpty(cert.getValueAsBytes()));
            CertificateToken certificateToken = DSSUtils.loadCertificate(cert.getValueAsBytes());
            assertNotNull(certificateToken);
        }
    }

    protected void checkSigningTime(CBORMap protectedHeaderMap) {
        CBORMap cwtClaim = protectedHeaderMap.getAsMap(CBORObjectFactory.toCBORObject(15L));
        assertNotNull(cwtClaim);

        Long iat = cwtClaim.getAsLong(CBORObjectFactory.toCBORObject(6L));
        assertNotNull(iat);

        Date date = new Date(iat * 1000L);
        assertNotNull(date);
        assertEquals(signatureParameters.bLevel().getSigningDate().getTime() / 1000L, iat);
    }

    protected void checkContentType(CBORMap protectedHeaderMap) {
        String contentType = protectedHeaderMap.getAsString(CBORObjectFactory.toCBORObject(3L));
        CBORMap sigD = protectedHeaderMap.getAsMap(CBORObjectFactory.toCBORObject(267L));
        assertTrue(contentType != null ^ sigD != null);

        if (contentType != null) {
            assertTrue(Utils.isStringNotEmpty(contentType));
            assertNotNull(MimeType.fromMimeTypeString(contentType));
        }
        if (sigD != null) {
            String mId = sigD.getAsString(CBORObjectFactory.toCBORObject(1));
            assertNotNull(mId);
            SigDMechanism sigDMechanism = SigDMechanism.forCBAdESUri(mId);
            assertNotNull(sigDMechanism);

            CBORArray pars = sigD.getAsArray(CBORObjectFactory.toCBORObject(2));
            assertNotNull(pars);
            assertFalse(pars.isEmpty());
            for (CBORObject par : pars.getValueAsList()) {
                assertTrue(par.isUnicodeString());
                assertTrue(Utils.isStringNotEmpty(((CBORSimpleObject) par).getValueAsString()));
            }

            if (SigDMechanism.OBJECT_ID_BY_URI == sigDMechanism) {
                Long hashM = sigD.getAsLong(CBORObjectFactory.toCBORObject(3));
                assertNull(hashM);

                CBORArray hashV = sigD.getAsArray(CBORObjectFactory.toCBORObject(4));
                assertNull(hashV);

            } else if (SigDMechanism.OBJECT_ID_BY_URI_HASH == sigDMechanism) {
                Long hashM = sigD.getAsLong(CBORObjectFactory.toCBORObject(3));
                assertNotNull(hashM);
                assertNotNull(DigestAlgorithm.forCOSE(hashM));

                CBORArray hashV = sigD.getAsArray(CBORObjectFactory.toCBORObject(4));
                assertNotNull(hashV);
                assertFalse(hashV.isEmpty());
                for (CBORObject par : hashV.getValueAsList()) {
                    assertTrue(par.isByteString());
                    assertTrue(Utils.isArrayNotEmpty(((CBORByteString) par).getValueAsBytes()));
                }

            }

            CBORArray ctys = sigD.getAsArray(CBORObjectFactory.toCBORObject(5));
            assertNotNull(ctys);
            assertFalse(ctys.isEmpty());
            for (CBORObject cty : ctys.getValueAsList()) {
                assertTrue(cty.isUnicodeString());
                assertTrue(Utils.isStringNotEmpty(((CBORSimpleObject) cty).getValueAsString()));
            }

        }
    }

    private void checkCrit(CBORMap protectedHeaderMap) {
        List<CBORObject> includedHeaders = Collections.singletonList(CBORObjectFactory.toCBORObject(267L)); // sigD

        List<CBORObject> presentHeaders = new ArrayList<>();
        for (CBORObject protectedHeaderKey : protectedHeaderMap.getKeys()) {
            if (includedHeaders.contains(protectedHeaderKey)) {
                presentHeaders.add(protectedHeaderKey);
            }
        }

        CBORArray crit = protectedHeaderMap.getAsArray(CBORObjectFactory.toCBORObject(2L));
        if (Utils.isCollectionNotEmpty(presentHeaders)) {
            assertNotNull(crit);
            assertFalse(crit.isEmpty());

            for (CBORObject critEntry : crit.getValueAsList()) {
                assertNotNull(critEntry);
                assertTrue(critEntry.isUnsignedInteger() || critEntry.isNegativeInteger());
                assertTrue(includedHeaders.contains(critEntry));
            }
        }
    }

    protected void checkSignatureValue(CBORByteString signatureValue) {
        assertNotNull(signatureValue);
        assertTrue(Utils.isArrayNotEmpty(signatureValue.getValueAsBytes()));
    }

    protected void checkUnprotectedHeader(CBORMap unprotectedHeaderMap) throws Exception {
        assertNotNull(unprotectedHeaderMap);

        checkSignatureTimestamp(unprotectedHeaderMap);
        checkValidationData(unprotectedHeaderMap);
        checkReferences(unprotectedHeaderMap);
        checkSigAndRefTimestamps(unprotectedHeaderMap);
        checkRefTimestamps(unprotectedHeaderMap);
        checkArchiveTimestamp(unprotectedHeaderMap);
    }

    protected void checkSignatureTimestamp(CBORMap unprotectedHeader) {
        CBORObject sigTst = getUHeadersElement(unprotectedHeader, COSEHeaderParameter.SIG_TST.cbor());
        checkTstContainer(sigTst);
    }

    protected CBORObject getUHeadersElement(CBORMap bodyUnprotectedHeader, CBORObject headerId) {
        CBORObject uHeaders = bodyUnprotectedHeader.getHeader(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertTrue(uHeaders.isArray());
        CBORArray uHeadersArray = (CBORArray) uHeaders;
        for (CBORObject uHeadersItem : uHeadersArray.getValueAsList()) {
            CBORMap map = null;
            if (uHeadersItem.isByteString()) {
                byte[] decoded = uHeadersItem.getValueAsBytes();
                CBORObject parsed = CBORUtils.parseCbor(decoded);
                assertTrue(parsed.isMap());
                map = (CBORMap) parsed;
            } else if (uHeadersItem.isMap()) {
                map = (CBORMap) uHeadersItem;
            } else {
                fail(String.format("The type of component '%s' of 'uHeaders' property is not supported!", uHeadersItem.getClass().getName()));
            }
            CBORObject value = map.getHeader(headerId);
            if (value != null) {
                return value;
            }
            // continue
        }
        return null;
    }

    protected void checkValidationData(CBORMap unprotectedHeaderMap) {
        CBORObject valData = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.VAL_DATA.cbor());
        assertNotNull(valData);
        assertTrue(valData.isMap());

        CBORMap valDataMap = (CBORMap) valData;

        CBORObject xVals = valDataMap.getHeader(COSEHeaderParameter.VAL_DATA_X_VALS.cbor());
        assertNotNull(xVals);
        assertTrue(xVals.isArray());

        CBORArray xValsArray = (CBORArray) xVals;
        assertFalse(xValsArray.isEmpty());

        for (CBORObject xValsItem : xValsArray.getValueAsList()) {
            assertTrue(xValsItem.isMap());
            CBORMap x509OrOther = (CBORMap) xValsItem;
            CBORObject x509Cert = x509OrOther.getHeader(COSEHeaderParameter.X509_OR_OTHER_X509_CERT.cbor());
            checkPkiOb(x509Cert);
        }

        CBORObject rVals = valDataMap.getHeader(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
        assertNotNull(rVals);
        assertTrue(rVals.isMap());

        CBORMap rValsMap = (CBORMap) rVals;

        CBORObject crlVals = rValsMap.getHeader(COSEHeaderParameter.R_VALS_CRL_VALS.cbor());
        assertNotNull(crlVals);
        assertTrue(crlVals.isArray());

        CBORArray crlValsArray = (CBORArray) crlVals;
        assertFalse(crlValsArray.isEmpty());
        for (CBORObject crlValsItem : crlValsArray.getValueAsList()) {
            checkPkiOb(crlValsItem);
        }
        CBORObject ocspVals = rValsMap.getHeader(COSEHeaderParameter.R_VALS_OCSP_VALS.cbor());
        assertNotNull(ocspVals);
        assertTrue(ocspVals.isArray());

        CBORArray ocspValsArray = (CBORArray) ocspVals;
        assertFalse(ocspValsArray.isEmpty());
        for (CBORObject ocspValsItem : ocspValsArray.getValueAsList()) {
            checkPkiOb(ocspValsItem);
        }
    }

    protected void checkPkiOb(CBORObject pkiOb) {
        assertNotNull(pkiOb);
        assertTrue(pkiOb.isMap());
        CBORMap pkiObMap = (CBORMap) pkiOb;
        byte[] binaries = pkiObMap.getAsBinaries(COSEHeaderParameter.PKI_OB_VAL.cbor());
        assertNotNull(binaries);
    }

    protected void checkReferences(CBORMap unprotectedHeaderMap) {
        CBORObject refs = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.REFS.cbor());
        assertNull(refs);
    }

    protected void checkSigAndRefTimestamps(CBORMap unprotectedHeaderMap) {
        CBORObject sigRTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.SIG_R_TST.cbor());
        assertNull(sigRTst);
    }

    protected void checkRefTimestamps(CBORMap unprotectedHeaderMap) {
        CBORObject rfsTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.RFS_TST.cbor());
        assertNull(rfsTst);
    }

    protected void checkArchiveTimestamp(CBORMap unprotectedHeaderMap) {
        CBORObject arcTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.ARC_TST.cbor());
        checkTstContainer(arcTst);
    }

    protected void checkTstContainer(CBORObject tstContainer) {
        assertNotNull(tstContainer);
        assertTrue(tstContainer.isMap());
        CBORMap tstContainerMap = (CBORMap) tstContainer;
        CBORObject tstTokens = tstContainerMap.getHeader(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
        assertNotNull(tstTokens);
        assertTrue(tstTokens.isArray());

        CBORArray tstTokensArray = (CBORArray) tstTokens;
        assertEquals(1, tstTokensArray.getSize());
        checkTstToken(tstTokensArray.getItem(0));
    }

    protected void checkTstToken(CBORObject tstToken) {
        assertTrue(tstToken.isMap());
        CBORMap tstTokenMap = (CBORMap) tstToken;
        assertNotNull(tstTokenMap.getAsBinaries(COSEHeaderParameter.TST_TOKEN_VAL.cbor()));
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
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
