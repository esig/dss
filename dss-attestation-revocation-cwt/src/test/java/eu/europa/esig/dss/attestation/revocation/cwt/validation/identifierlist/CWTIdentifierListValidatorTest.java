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
package eu.europa.esig.dss.attestation.revocation.cwt.validation.identifierlist;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CWTIdentifierListValidatorTest {

    @Test
    void cwtIdentifierListTest() {
        /* See ISO/IEC 18013-5 "D.6 MSO revocation list examples" */

        String tokenHex =
                "D284581BA3012610716964656E74666965726C6973742B637774182142AAAAA0589BA" +
                        "502782568747470733A2F2F6578616D706C652E636F6D2F6964656E746966" +
                        "6965726C697374732F31041A8898DFEA061A648C5BEA19FFFE1A000151801" +
                        "9FFFAA26B6964656E74696669657273A342ABCDA042AAAAA042CCCCA06F61" +
                        "67677265676174696F6E5F757269782F68747470733A2F2F6578616D706C6" +
                        "52E636F6D2F6964656E7469666965726C697374732F616767726567617469" +
                        "6F6E42AAAA";

        byte[] tokenBytes = Utils.fromHex(tokenHex);

        assertTrue(new CWTIdentifierListValidator().isSupported(tokenBytes));

        CWTIdentifierListValidator validator = new CWTIdentifierListValidator(tokenBytes);

        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(Utils.fromHex("aaaa")).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(Utils.fromHex("bbbb")).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(Utils.fromHex("cccc")).getStatus());
        assertEquals(AttestationStatus.INVALID, validator.getRevocationToken(Utils.fromHex("abcd")).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(Utils.fromHex("dcba")).getStatus());

        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(new byte[] {}).getStatus());
        assertEquals(AttestationStatus.VALID, validator.getRevocationToken(new byte[] { 1 }).getStatus());
    }

}
