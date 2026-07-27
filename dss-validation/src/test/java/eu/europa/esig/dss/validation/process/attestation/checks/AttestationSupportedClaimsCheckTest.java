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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.MultiValuesConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttestationSupportedClaimsCheckTest extends AbstractTestCheck {

    @Test
    void validTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("metadata");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlVerifiableCredentialsTypeClaim.setName("metadata");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedClaimsCheck supportedClaimsCheck = new AttestationSupportedClaimsCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        supportedClaimsCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

    @Test
    void invalidTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("metadata");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlVerifiableCredentialsTypeClaim.setName("metadata-wrong");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);
        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedClaimsCheck supportedClaimsCheck = new AttestationSupportedClaimsCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        supportedClaimsCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void additionalClaimTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("metadata");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlVerifiableCredentialsTypeClaim.setName("metadata");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        XmlClaim xmlClaim = new XmlClaim();
        xmlClaim.setName("additional");
        xmlAttestationPayload.getOtherClaim().add(xmlClaim);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedClaimsCheck supportedClaimsCheck = new AttestationSupportedClaimsCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        supportedClaimsCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
    }

    @Test
    void notPresentClaimTest() {
        MultiValuesConstraint constraint = new MultiValuesConstraint();
        constraint.getId().add("metadata");
        constraint.getId().add("additional");
        constraint.setLevel(Level.FAIL);

        XmlAttestation xmlAttestation = new XmlAttestation();
        xmlAttestation.setProfile(AttestationProfile.SD_JWT_VC);
        XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();
        XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsTypeClaim = new XmlVerifiableCredentialsTypeClaim();
        xmlVerifiableCredentialsTypeClaim.setText("urn:eudi:pid:1");
        xmlVerifiableCredentialsTypeClaim.setName("metadata");
        xmlAttestationPayload.setVerifiableCredentialsType(xmlVerifiableCredentialsTypeClaim);

        xmlAttestation.setAttestationPayload(xmlAttestationPayload);

        XmlSAV result = new XmlSAV();

        AttestationSupportedClaimsCheck supportedClaimsCheck = new AttestationSupportedClaimsCheck(
                i18nProvider, result, new AttestationWrapper(xmlAttestation), new MultiValuesConstraintWrapper(constraint));
        supportedClaimsCheck.execute();

        List<XmlConstraint> constraints = result.getConstraint();
        assertEquals(1, constraints.size());
        assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
    }

}
