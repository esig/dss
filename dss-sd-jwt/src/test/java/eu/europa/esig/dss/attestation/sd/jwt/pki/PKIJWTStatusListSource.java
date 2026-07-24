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
package eu.europa.esig.dss.attestation.sd.jwt.pki;

import eu.europa.esig.dss.attestation.common.pki.PKIAttestationStatusListSource;
import eu.europa.esig.dss.attestation.revocation.jwt.model.statuslist.JWTStatusListClaimNames;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.jwt.JWTClaimNames;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.attestation.claim.ClaimStatus;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.jose4j.json.internal.json_simple.JSONObject;

import java.util.Collections;

public class PKIJWTStatusListSource extends PKIAttestationStatusListSource<JAdESSignatureParameters> {

    /**
     * Creates a PKIJWTStatusListSource instance with revocation list signer {@code CertEntity}
     *
     * @param certEntityRepository {@link CertEntityRepository}
     * @param statusListIssuer     {@link CertEntity} to issue revocation list
     */
    public PKIJWTStatusListSource(CertEntityRepository<? extends CertEntity> certEntityRepository, CertEntity statusListIssuer) {
        super(certEntityRepository, statusListIssuer);
    }

    @Override
    public String getType() {
        String type = super.getType();
        if (type == null) {
            return "statuslist+jwt";
        }
        return type;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(getIssuanceTime());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setSigningCertificate(statusListIssuer.getCertificateToken());
        signatureParameters.setCertificateChain(Collections.singletonList(statusListIssuer.getCertificateToken()));
        signatureParameters.setSignatureType(getType());
        return signatureParameters;
    }

    @Override
    protected JAdESService getService() {
        return new JAdESService(new CommonCertificateVerifier());
    }

    /**
     * Generates payload
     *
     * @param claimStatus {@link ClaimStatus}
     * @return {@link DSSDocument}
     */
    @Override
    protected DSSDocument generatePayload(ClaimStatus claimStatus) {
        JSONObject statusListPayload = new JSONObject();

        statusListPayload.put(JWTClaimNames.IAT, DSSUtils.getTimeValueInSeconds(getIssuanceTime().getTime()));
        statusListPayload.put(JWTClaimNames.EXP, DSSUtils.getTimeValueInSeconds(getExpirationTime().getTime()));
        if (getTimeToLive() != null) {
            statusListPayload.put(JWTStatusListClaimNames.TTL, getTimeToLive());
        }

        JSONObject statusList = new JSONObject();
        statusList.put(JWTStatusListClaimNames.BITS, 1);
        statusList.put(JWTStatusListClaimNames.LST, createLst(getStatusList()));
        statusListPayload.put(JWTStatusListClaimNames.STATUS_LIST, statusList);

        if (claimStatus != null) {
            if (claimStatus.getUri() != null) {
                statusListPayload.put(JWTClaimNames.SUB, claimStatus.getUri().getStringValue());
            }
            if (claimStatus.getStatusList() != null && claimStatus.getStatusList().getUri() != null) {
                statusListPayload.put(JWTClaimNames.SUB, claimStatus.getStatusList().getUri().getStringValue());
            }
        }

        return new InMemoryDocument(statusListPayload.toJSONString().getBytes());
    }

    /**
     * Creates "lst" entry
     *
     * @param bytes byte array
     * @return {@link String}
     */
    protected String createLst(byte[] bytes) {
        byte[] compressed = compressZlib(bytes);
        return DSSJsonUtils.toBase64Url(compressed);
    }

}
