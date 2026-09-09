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

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.cbor.CBORValueFactory;
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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCBAdESRequirementsCheck extends AbstractCBAdESTestSignature {

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
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
            CBORValue payload = getPayload(byteArray);
            checkPayload(payload);

            CBORValue protectedHeader = getProtectedHeader(byteArray);
            checkProtectedHeader(protectedHeader);

            CBORValue signatureValue = getSignatureValue(byteArray);
            checkSignatureValue(signatureValue);

            CBORValue unprotectedHeader = getUnprotectedHeader(byteArray);
            checkUnprotectedHeader(unprotectedHeader);

        } catch (Exception e) {
            fail(e);
        }
    }

    protected abstract CBORValue getPayload(byte[] byteArray) throws Exception;

    protected abstract CBORValue getProtectedHeader(byte[] byteArray) throws Exception;

    protected abstract CBORValue getSignatureValue(byte[] byteArray) throws Exception;

    protected abstract CBORValue getUnprotectedHeader(byte[] byteArray) throws Exception;

    protected void checkPayload(CBORValue payload) {
        assertNotNull(payload);
        assertTrue(Utils.isArrayNotEmpty(payload.asBytes()));
    }

    protected void checkProtectedHeader(CBORValue protectedHeader) {
        assertNotNull(protectedHeader);
        assertTrue(Utils.isArrayNotEmpty(protectedHeader.asBytes()));

        CBORValue protectedHeaderMap = CBORUtils.parseCbor(protectedHeader.asBytes());
        assertTrue(protectedHeaderMap.isMap());

        assertTrue(protectedHeaderMap.size() > 0);

        checkSigningCertificate(protectedHeaderMap);
        checkCertificateChain(protectedHeaderMap);
        checkSigningTime(protectedHeaderMap);
        checkContentType(protectedHeaderMap);
        checkCrit(protectedHeaderMap);
    }

    protected void checkSigningCertificate(CBORValue protectedHeaderMap) {
        CBORValue x5t = protectedHeaderMap.getAsArrayOrNull(CBORValueFactory.toCBORValue(34L));
        CBORValue x5ts = protectedHeaderMap.getAsArrayOrNull(CBORValueFactory.toCBORValue(261L));
        assertTrue(x5t != null ^ x5ts != null);

        if (x5t != null) {
            BigInteger hashAlg = x5t.getAsIntegerOrNull(0);
            assertNotNull(hashAlg);
            assertNotNull(DigestAlgorithm.forCOSE(hashAlg.longValue()));

            byte[] hashVal = x5t.getAsBytesOrNull(1);
            assertNotNull(hashVal);
            assertTrue(Utils.isArrayNotEmpty(hashVal));
        }

        if (x5ts != null) {
            assertTrue(x5ts.size() > 0);

            for (CBORValue x5tItem : x5ts.getElements()) {
                assertTrue(x5tItem.isArray());

                BigInteger hashAlg = x5tItem.getAsIntegerOrNull(0);
                assertNotNull(hashAlg);
                assertNotNull(DigestAlgorithm.forCOSE(hashAlg.longValue()));

                byte[] hashVal = x5tItem.getAsBytesOrNull(1);
                assertNotNull(hashVal);
                assertTrue(Utils.isArrayNotEmpty(hashVal));
            }
        }
    }

    private void checkCertificateChain(CBORValue protectedHeaderMap) {
        CBORValue x5chain = protectedHeaderMap.getAsArrayOrNull(CBORValueFactory.toCBORValue(33L));
        assertNotNull(x5chain);
        assertTrue(x5chain.size() > 0);
        for (CBORValue cert : x5chain.getElements()) {
            assertNotNull(cert);
            assertTrue(cert.isByteString());

            assertTrue(Utils.isArrayNotEmpty(cert.asBytes()));
            CertificateToken certificateToken = DSSUtils.loadCertificate(cert.asBytes());
            assertNotNull(certificateToken);
        }
    }

    protected void checkSigningTime(CBORValue protectedHeaderMap) {
        CBORValue cwtClaim = protectedHeaderMap.getAsMapOrNull(CBORValueFactory.toCBORValue(15L));
        assertNotNull(cwtClaim);

        BigInteger iat = cwtClaim.getAsIntegerOrNull(CBORValueFactory.toCBORValue(6L));
        assertNotNull(iat);

        Date date = new Date(iat.longValue() * 1000L);
        assertNotNull(date);
        assertEquals(signatureParameters.bLevel().getSigningDate().getTime() / 1000L, iat.longValue());
    }

    protected void checkContentType(CBORValue protectedHeaderMap) {
        String contentType = protectedHeaderMap.getAsStringOrNull(CBORValueFactory.toCBORValue(3L));
        CBORValue sigD = protectedHeaderMap.getAsMapOrNull(CBORValueFactory.toCBORValue(267L));
        assertTrue(contentType != null ^ sigD != null);

        if (contentType != null) {
            assertTrue(Utils.isStringNotEmpty(contentType));
            assertNotNull(MimeType.fromMimeTypeString(contentType));
        }
        if (sigD != null) {
            String mId = sigD.getAsStringOrNull(CBORValueFactory.toCBORValue(1));
            assertNotNull(mId);
            SigDMechanism sigDMechanism = SigDMechanism.forCBAdESUri(mId);
            assertNotNull(sigDMechanism);

            CBORValue pars = sigD.getAsArrayOrNull(CBORValueFactory.toCBORValue(2));
            assertNotNull(pars);
            assertTrue(pars.size() > 0);
            for (CBORValue par : pars.getElements()) {
                assertTrue(par.isTextString());
                assertTrue(Utils.isStringNotEmpty(par.asString()));
            }

            if (SigDMechanism.OBJECT_ID_BY_URI == sigDMechanism) {
                BigInteger hashM = sigD.getAsIntegerOrNull(CBORValueFactory.toCBORValue(3));
                assertNull(hashM);

                CBORValue hashV = sigD.getAsArrayOrNull(CBORValueFactory.toCBORValue(4));
                assertNull(hashV);

            } else if (SigDMechanism.OBJECT_ID_BY_URI_HASH == sigDMechanism) {
                BigInteger hashM = sigD.getAsIntegerOrNull(CBORValueFactory.toCBORValue(3));
                assertNotNull(hashM);
                assertNotNull(DigestAlgorithm.forCOSE(hashM.longValue()));

                CBORValue hashV = sigD.getAsArrayOrNull(CBORValueFactory.toCBORValue(4));
                assertNotNull(hashV);
                assertTrue(hashV.size() > 0);
                for (CBORValue par : hashV.getElements()) {
                    assertTrue(par.isByteString());
                    assertTrue(Utils.isArrayNotEmpty(par.asBytes()));
                }

            }

            CBORValue ctys = sigD.getAsArrayOrNull(CBORValueFactory.toCBORValue(5));
            assertNotNull(ctys);
            assertTrue(ctys.size() > 0);
            for (CBORValue cty : ctys.getElements()) {
                assertTrue(cty.isTextString());
                assertTrue(Utils.isStringNotEmpty(cty.asString()));
            }

        }
    }

    private void checkCrit(CBORValue protectedHeaderMap) {
        List<CBORValue> includedHeaders = Collections.singletonList(CBORValueFactory.toCBORValue(267L)); // sigD

        List<CBORValue> presentHeaders = new ArrayList<>();
        for (CBORValue protectedHeaderKey : protectedHeaderMap.getKeys()) {
            if (includedHeaders.contains(protectedHeaderKey)) {
                presentHeaders.add(protectedHeaderKey);
            }
        }

        CBORValue crit = protectedHeaderMap.getAsArrayOrNull(CBORValueFactory.toCBORValue(2L));
        if (Utils.isCollectionNotEmpty(presentHeaders)) {
            assertNotNull(crit);
            assertTrue(crit.size() > 0);

            for (CBORValue critEntry : crit.getElements()) {
                assertNotNull(critEntry);
                assertTrue(critEntry.isUnsignedInteger() || critEntry.isNegativeInteger());
                assertTrue(includedHeaders.contains(critEntry));
            }
        }
    }

    protected void checkSignatureValue(CBORValue signatureValue) {
        assertNotNull(signatureValue);
        assertTrue(Utils.isArrayNotEmpty(signatureValue.asBytes()));
    }

    protected void checkUnprotectedHeader(CBORValue unprotectedHeaderMap) {
        assertNotNull(unprotectedHeaderMap);

        checkSignatureTimestamp(unprotectedHeaderMap);
        checkValidationData(unprotectedHeaderMap);
        checkReferences(unprotectedHeaderMap);
        checkSigAndRefTimestamps(unprotectedHeaderMap);
        checkRefTimestamps(unprotectedHeaderMap);
        checkArchiveTimestamp(unprotectedHeaderMap);
    }

    protected void checkSignatureTimestamp(CBORValue unprotectedHeader) {
        CBORValue sigTst = getUHeadersElement(unprotectedHeader, COSEHeaderParameter.SIG_TST.cbor());
        checkTstContainer(sigTst);
    }

    protected CBORValue getUHeadersElement(CBORValue bodyUnprotectedHeader, CBORValue headerId) {
        CBORValue uHeaders = bodyUnprotectedHeader.get(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertTrue(uHeaders.isArray());
        for (CBORValue uHeadersItem : uHeaders.getElements()) {
            CBORValue map = null;
            if (uHeadersItem.isByteString()) {
                byte[] decoded = uHeadersItem.asBytes();
                CBORValue parsed = CBORUtils.parseCbor(decoded);
                assertTrue(parsed.isMap());
                map = parsed;
            } else if (uHeadersItem.isMap()) {
                map = uHeadersItem;
            } else {
                fail(String.format("The type of component '%s' of 'uHeaders' property is not supported!", uHeadersItem.getClass().getName()));
            }
            CBORValue value = map.get(headerId);
            if (value != null) {
                return value;
            }
            // continue
        }
        return null;
    }

    protected void checkValidationData(CBORValue unprotectedHeaderMap) {
        CBORValue valData = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.VAL_DATA.cbor());
        assertNotNull(valData);
        assertTrue(valData.isMap());

        CBORValue xVals = valData.get(COSEHeaderParameter.VAL_DATA_X_VALS.cbor());
        assertNotNull(xVals);
        assertTrue(xVals.isArray());

        assertTrue(xVals.size() > 0);

        for (CBORValue x509OrOther : xVals.getElements()) {
            assertTrue(x509OrOther.isMap());
            CBORValue x509Cert = x509OrOther.get(COSEHeaderParameter.X509_OR_OTHER_X509_CERT.cbor());
            checkPkiOb(x509Cert);
        }

        CBORValue rVals = valData.get(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
        assertNotNull(rVals);
        assertTrue(rVals.isMap());

        CBORValue crlVals = rVals.get(COSEHeaderParameter.R_VALS_CRL_VALS.cbor());
        assertNotNull(crlVals);
        assertTrue(crlVals.isArray());

        assertTrue(crlVals.size() > 0);
        for (CBORValue crlValsItem : crlVals.getElements()) {
            checkPkiOb(crlValsItem);
        }
        CBORValue ocspVals = rVals.get(COSEHeaderParameter.R_VALS_OCSP_VALS.cbor());
        assertNotNull(ocspVals);
        assertTrue(ocspVals.isArray());

        assertTrue(ocspVals.size() > 0);
        for (CBORValue ocspValsItem : ocspVals.getElements()) {
            checkPkiOb(ocspValsItem);
        }
    }

    protected void checkPkiOb(CBORValue pkiOb) {
        assertNotNull(pkiOb);
        assertTrue(pkiOb.isMap());
        byte[] binaries = pkiOb.getAsBytesOrNull(COSEHeaderParameter.PKI_OB_VAL.cbor());
        assertNotNull(binaries);
    }

    protected void checkReferences(CBORValue unprotectedHeaderMap) {
        CBORValue refs = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.REFS.cbor());
        assertNull(refs);
    }

    protected void checkSigAndRefTimestamps(CBORValue unprotectedHeaderMap) {
        CBORValue sigRTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.SIG_R_TST.cbor());
        assertNull(sigRTst);
    }

    protected void checkRefTimestamps(CBORValue unprotectedHeaderMap) {
        CBORValue rfsTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.RFS_TST.cbor());
        assertNull(rfsTst);
    }

    protected void checkArchiveTimestamp(CBORValue unprotectedHeaderMap) {
        CBORValue arcTst = getUHeadersElement(unprotectedHeaderMap, COSEHeaderParameter.ARC_TST.cbor());
        checkTstContainer(arcTst);
    }

    protected void checkTstContainer(CBORValue tstContainer) {
        assertNotNull(tstContainer);
        assertTrue(tstContainer.isMap());
        CBORValue tstTokens = tstContainer.get(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
        assertNotNull(tstTokens);
        assertTrue(tstTokens.isArray());

        assertEquals(1, tstTokens.size());
        checkTstToken(tstTokens.get(0));
    }

    protected void checkTstToken(CBORValue tstToken) {
        assertTrue(tstToken.isMap());
        assertNotNull(tstToken.getAsBytesOrNull(COSEHeaderParameter.TST_TOKEN_VAL.cbor()));
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
