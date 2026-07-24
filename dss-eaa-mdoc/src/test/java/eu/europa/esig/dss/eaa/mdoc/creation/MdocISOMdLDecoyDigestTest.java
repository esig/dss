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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class MdocISOMdLDecoyDigestTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    private Date expirationDate;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 3);
        expirationDate = calendar.getTime();

        payloadParameters.setExpirationDate(expirationDate);

        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setBirthdate(DSSUtils.getUtcDate(2001, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeIssuanceDate(DSSUtils.getUtcDate(2026, Calendar.JUNE, 1));
        payloadParameters.selectivelyDisclosable().setAdministrativeExpirationDate(DSSUtils.getUtcDate(2026, Calendar.AUGUST, 31));
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("123456789");
        payloadParameters.selectivelyDisclosable().setPortrait(Utils.fromBase64("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAA+SURBVDhPY/hPIWBAFyAVUNeAr7VN/z/6BiMLwcH3qTP/vzexRhceNQCbAW9lVHBiogyg2AUj3QByAMUGAAAAZ7ueWC72UQAAAABJRU5ErkJggg=="));

        MdocDrivingPrivilege mdocDrivingPrivilege = new MdocDrivingPrivilege("B");
        mdocDrivingPrivilege.setIssueDate(DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1));
        mdocDrivingPrivilege.setExpiryDate(DSSUtils.getUtcDate(2030, Calendar.JANUARY, 1));
        payloadParameters.selectivelyDisclosable().setDrivingPrivileges(mdocDrivingPrivilege);

        payloadParameters.selectivelyDisclosable().setDistinguishingSign("DN");

        payloadParameters.setDecoyDigestNumber(2);

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected List<MdocSelectiveDisclosure> getDisclosures() {
        List<MdocSelectiveDisclosure> originalDisclosures = super.getDisclosures();
        List<MdocSelectiveDisclosure> repeatedDisclosures = super.getDisclosures();

        assertEquals(11, originalDisclosures.size());
        assertEquals(originalDisclosures, repeatedDisclosures);
        assertEquals(getDigestMap(originalDisclosures), getDigestMap(repeatedDisclosures));
        assertEquals(getSaltMap(originalDisclosures), getSaltMap(repeatedDisclosures));

        payloadParameters.setExpirationDate(new Date());
        List<MdocSelectiveDisclosure> updatedDisclosures = super.getDisclosures();

        assertNotEquals(originalDisclosures, updatedDisclosures);
        assertNotEquals(new HashSet<>(originalDisclosures), new HashSet<>(updatedDisclosures));
        assertNotEquals(getDigestMap(originalDisclosures), getDigestMap(updatedDisclosures));
        assertNotEquals(getSaltMap(originalDisclosures), getSaltMap(updatedDisclosures));

        payloadParameters.setExpirationDate(expirationDate);
        return originalDisclosures;
    }

    private Map<String, Long> getDigestMap(List<MdocSelectiveDisclosure> disclosures) {
        Map<String, Long> digestMap = new HashMap<>();
        for (MdocSelectiveDisclosure disclosure : disclosures) {
            CBORMap element = (CBORMap) CBORUtils.parseCbor(disclosure.getIssuerSignedItemBytes().getValueAsBytes());
            digestMap.put(element.getAsString("elementIdentifier"), element.getAsLong("digestID"));
        }
        return digestMap;
    }

    private Map<String, String> getSaltMap(List<MdocSelectiveDisclosure> disclosures) {
        Map<String, String> saltMap = new HashMap<>();
        for (MdocSelectiveDisclosure disclosure : disclosures) {
            CBORMap element = (CBORMap) CBORUtils.parseCbor(disclosure.getIssuerSignedItemBytes().getValueAsBytes());
            saltMap.put(element.getAsString("elementIdentifier"), Utils.toBase64(element.getAsBinaries("random")));
        }
        return saltMap;
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
