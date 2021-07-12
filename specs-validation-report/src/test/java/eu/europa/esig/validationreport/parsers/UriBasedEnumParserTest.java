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
package eu.europa.esig.validationreport.parsers;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.validationreport.enums.ConstraintStatus;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class UriBasedEnumParserTest {

    @Test
    void mainStatusIndication() {
        for (Indication msi : Indication.values()) {
            String string = UriBasedEnumParser.print(msi);
            assertNotNull(string);
            assertEquals(msi, UriBasedEnumParser.parseMainIndication(string));
        }
    }

    @Test
    void objectType() {
        for (ObjectType ot : ObjectType.values()) {
            String string = UriBasedEnumParser.print(ot);
            assertNotNull(string);
            assertEquals(ot, UriBasedEnumParser.parseObjectType(string));
        }
    }

    @Test
    void revocationReason() {
        for (RevocationReason rr : RevocationReason.values()) {
            String string = UriBasedEnumParser.print(rr);
            assertNotNull(string);
            assertEquals(rr, UriBasedEnumParser.parseRevocationReason(string));
        }
    }

    @Test
    void signatureValidationProcessID() {
        for (SignatureValidationProcessID svpid : SignatureValidationProcessID.values()) {
            String string = UriBasedEnumParser.print(svpid);
            assertNotNull(string);
            assertEquals(svpid, UriBasedEnumParser.parseSignatureValidationProcessID(string));
        }
    }

    @Test
    void statusSubIndication() {
        for (SubIndication ssi : SubIndication.values()) {
            String string = UriBasedEnumParser.print(ssi);
            assertNotNull(string);
            assertEquals(ssi, UriBasedEnumParser.parseSubIndication(string));
        }
    }

    @Test
    void typeOfProof() {
        for (TypeOfProof top : TypeOfProof.values()) {
            String string = UriBasedEnumParser.print(top);
            assertNotNull(string);
            assertEquals(top, UriBasedEnumParser.parseTypeOfProof(string));
        }
    }

    @Test
    void constraintStatus() {
        for (ConstraintStatus cs : ConstraintStatus.values()) {
            String string = UriBasedEnumParser.print(cs);
            assertNotNull(string);
            assertEquals(cs, UriBasedEnumParser.parseConstraintStatus(string));
        }
    }

    @Test
    void nullValues() {
        assertNull(UriBasedEnumParser.print(null));
        assertNull(UriBasedEnumParser.parseConstraintStatus(null));
    }

}
