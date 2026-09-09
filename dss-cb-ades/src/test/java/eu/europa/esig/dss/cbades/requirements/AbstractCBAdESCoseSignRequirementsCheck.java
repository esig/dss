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
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCBAdESCoseSignRequirementsCheck extends AbstractCBAdESRequirementsCheck {

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        try {
            CBORValue protectedHeader = getBodyProtectedHeader(byteArray);
            checkBodyProtectedHeader(protectedHeader);

            CBORValue unprotectedHeader = getBodyUnprotectedHeader(byteArray);
            checkBodyUnprotectedHeader(unprotectedHeader);

        } catch (Exception e) {
            fail(e);
        }
    }

    @Override
    protected CBORValue getPayload(byte[] byteArray) throws Exception {
        CBORValue cose = getCose(byteArray);
        CBORValue payloadObject = cose.getElements().get(2);
        assertTrue(payloadObject.isByteString());
        return payloadObject;
    }

    protected CBORValue getBodyProtectedHeader(byte[] byteArray) {
        CBORValue cose = getCose(byteArray);
        CBORValue protectedHeader = cose.getElements().get(0);
        assertTrue(protectedHeader.isByteString());
        return protectedHeader;
    }

    @Override
    protected CBORValue getProtectedHeader(byte[] byteArray) throws Exception {
        CBORValue cose = getCose(byteArray);
        CBORValue coseSignature = getCoseSignature(cose);
        CBORValue protectedHeader = coseSignature.getElements().get(0);
        assertTrue(protectedHeader.isByteString());
        return protectedHeader;
    }

    @Override
    protected CBORValue getSignatureValue(byte[] byteArray) throws Exception {
        CBORValue cose = getCose(byteArray);
        CBORValue coseSignature = getCoseSignature(cose);
        CBORValue signature = coseSignature.getElements().get(2);
        assertTrue(signature.isByteString());
        return signature;
    }

    protected CBORValue getBodyUnprotectedHeader(byte[] byteArray) throws Exception {
        CBORValue cose = getCose(byteArray);
        CBORValue unprotectedHeader = cose.getElements().get(1);
        assertTrue(unprotectedHeader.isMap());
        return unprotectedHeader;
    }

    @Override
    protected CBORValue getUnprotectedHeader(byte[] byteArray) throws Exception {
        CBORValue cose = getCose(byteArray);
        CBORValue coseSignature = getCoseSignature(cose);
        CBORValue unprotectedHeader = coseSignature.getElements().get(1);
        assertTrue(unprotectedHeader.isMap());

        return unprotectedHeader;
    }

    private CBORValue getCose(byte[] byteArray) {
        CBORValue cborValue = CBORUtils.parseCbor(byteArray);
        assertTrue(cborValue.isTag());
        cborValue = cborValue.getTaggedValue();
        assertNotNull(cborValue);
        assertTrue(cborValue.isArray());
        assertEquals(4, cborValue.size());
        return cborValue;
    }

    private CBORValue getCoseSignature(CBORValue cose) {
        CBORValue signatures = cose.getElements().get(3);
        assertTrue(signatures.isArray());
        assertEquals(1, signatures.size());

        CBORValue signature = signatures.getAsArrayOrNull(0);
        assertNotNull(signature);
        assertEquals(3, signature.size());
        return signature;
    }

    protected void checkBodyProtectedHeader(CBORValue bodyProtectedHeader) {
        assertNotNull(bodyProtectedHeader);
        assertTrue(Utils.isArrayNotEmpty(bodyProtectedHeader.asBytes()));

        CBORValue protectedHeaderObject = CBORUtils.parseCbor(bodyProtectedHeader.asBytes());
        assertTrue(protectedHeaderObject.isMap());

        assertEquals(0, protectedHeaderObject.size());
    }

    protected void checkBodyUnprotectedHeader(CBORValue bodyUnprotectedHeader) {
        assertNotNull(bodyUnprotectedHeader);
        assertEquals(0, bodyUnprotectedHeader.size());
    }

}
