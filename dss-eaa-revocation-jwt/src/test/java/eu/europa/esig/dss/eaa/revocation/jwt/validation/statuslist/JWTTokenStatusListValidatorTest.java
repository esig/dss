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
package eu.europa.esig.dss.eaa.revocation.jwt.validation.statuslist;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.model.DSSException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTTokenStatusListValidatorTest {

    @Test
    void jwtStatusListTest() {
        /* See draft-ietf-oauth-status-list-20 */

        String tokenB64Url =
                "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.e" +
                "yJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9le" +
                "GFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQ" +
                "WhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsI" +
                "nR0bCI6NDMyMDB9.2lKUUNG503R9htu4aHAYi7vjmr3sgApbfoDvPrl65N3URUO1EYqq" +
                "Ql45Jfzd-Av4QzlKa3oVALpLwOEUOq-U_g";

        assertTrue(new JWTTokenStatusListValidator().isSupported(tokenB64Url.getBytes()));

        JWTTokenStatusListValidator validator = new JWTTokenStatusListValidator(tokenB64Url.getBytes());

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
