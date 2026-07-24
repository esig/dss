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
package eu.europa.esig.dss.attestation.mdoc.pki;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.cwt.CWTClaims;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.attestation.common.pki.PKIAttestationStatusListSource;
import eu.europa.esig.dss.attestation.revocation.cwt.model.statuslist.CWTStatusListClaims;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.attestation.claim.ClaimStatus;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.util.Collections;

/**
 * Test implementation for generation of CWT-encoded Token Status List
 *
 */
public class PKICWTStatusListSource extends PKIAttestationStatusListSource<CBAdESSignatureParameters> {

    /**
     * Creates a PKIJWTStatusListSource instance with revocation list signer {@code CertEntity}
     *
     * @param certEntityRepository {@link CertEntityRepository}
     * @param statusListIssuer     {@link CertEntity} to issue revocation list
     */
    public PKICWTStatusListSource(CertEntityRepository<? extends CertEntity> certEntityRepository, CertEntity statusListIssuer) {
        super(certEntityRepository, statusListIssuer);
    }

    @Override
    public String getType() {
        String type = super.getType();
        if (type == null) {
            return "application/statuslist+cwt";
        }
        return type;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(getIssuanceTime());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setTagged(true);
        signatureParameters.setSigningCertificate(statusListIssuer.getCertificateToken());
        signatureParameters.setCertificateChain(Collections.singletonList(statusListIssuer.getCertificateToken()));
        signatureParameters.setSignatureType(getType());
        return signatureParameters;
    }

    @Override
    protected CBAdESService getService() {
        return new CBAdESService(new CommonCertificateVerifier());
    }

    /**
     * Generates payload
     *
     * @param claimStatus {@link ClaimStatus}
     * @return {@link DSSDocument}
     */
    @Override
    protected DSSDocument generatePayload(ClaimStatus claimStatus) {
        CBORMap statusListPayload = new CBORMap();

        statusListPayload.put(CWTClaims.IAT.cbor(), DSSUtils.getTimeValueInSeconds(getIssuanceTime().getTime()));
        statusListPayload.put(CWTClaims.EXP.cbor(), DSSUtils.getTimeValueInSeconds(getExpirationTime().getTime()));
        if (getTimeToLive() != null) {
            statusListPayload.put(CWTStatusListClaims.TIME_TO_LIVE, getTimeToLive());
        }

        CBORMap statusList = new CBORMap();
        statusList.put(CWTStatusListClaims.STATUS_LIST_BITS.cbor(), 1);
        statusList.put(CWTStatusListClaims.STATUS_LIST_LST.cbor(), compressZlib(getStatusList()));
        statusListPayload.put(CWTStatusListClaims.STATUS_LIST.cbor(), statusList);

        if (claimStatus != null && claimStatus.getStatusList() != null && claimStatus.getStatusList().getUri() != null) {
            statusListPayload.put(CWTClaims.SUB.cbor(), claimStatus.getStatusList().getUri().getStringValue());
        }

        return new InMemoryDocument(CBORUtils.serializeCborObject(statusListPayload));
    }

}
