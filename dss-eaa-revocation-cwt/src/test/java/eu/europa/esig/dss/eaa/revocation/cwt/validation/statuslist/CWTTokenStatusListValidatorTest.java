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
package eu.europa.esig.dss.eaa.revocation.cwt.validation.statuslist;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CWTTokenStatusListValidatorTest {

    @Test
    void cwtStatusListTest() {
        /* See draft-ietf-oauth-status-list-20 */

        String tokenHex =
                "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b63" +
                        "7774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f73" +
                        "74617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2" +
                        "646269747301636c73744a78dadbb918000217015d584093fa4d01032b18c35e2fe1" +
                        "101b77fd6cc9440022caa4694450c4e4e9feab4e99d1fa6d9772ce2bf3a12e0323de" +
                        "d7c982c5e101a5e67f0cbc1e2b6f57ce99c279";

        byte[] tokenBytes = Utils.fromHex(tokenHex);

        assertTrue(new CWTTokenStatusListValidator().isSupported(tokenBytes));

        CWTTokenStatusListValidator validator = new CWTTokenStatusListValidator(tokenBytes);

        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(0).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(1).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(2).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(3).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(4).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(5).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(6).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(7).getStatus());

        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(8).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(9).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(10).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(11).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(12).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(13).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(14).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(15).getStatus());

        Exception exception = assertThrows(DSSException.class, () -> validator.getRevocationToken(16));
        assertEquals("The position of the index '16' is out of bounds of " +
                "the obtained status list array with size '2' bytes (16 bits)!", exception.getMessage());
    }

}
