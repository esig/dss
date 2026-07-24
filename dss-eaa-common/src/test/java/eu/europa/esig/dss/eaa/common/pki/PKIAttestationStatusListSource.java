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
package eu.europa.esig.dss.eaa.common.pki;

import eu.europa.esig.dss.eaa.revocation.source.ExternalResourcesAttestationRevocationSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.eaa.Attestation;
import eu.europa.esig.dss.spi.eaa.AttestationRevocationToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public abstract class PKIAttestationStatusListSource<T extends SerializableSignatureParameters> extends AbstractPKIAttestationRevocationListSource<T> {

    /**
     * Status list array
     */
    protected byte[] statusList = new byte[8];

    /**
     * Creates a PKIJWTStatusListSource instance with status list signer {@code CertEntity}
     *
     * @param certEntityRepository {@link CertEntityRepository}
     * @param statusListIssuer     {@link CertEntity} to issue status list
     */
    protected PKIAttestationStatusListSource(CertEntityRepository<? extends CertEntity> certEntityRepository, CertEntity statusListIssuer) {
        super(certEntityRepository, statusListIssuer);
    }

    public byte[] getStatusList() {
        return statusList;
    }

    public void setStatusList(byte[] statusList) {
        this.statusList = statusList;
    }

    @Override
    public AttestationRevocationToken getAttestationRevocation(Attestation attestation) {
        if (attestation != null && attestation.getPayload() != null && attestation.getPayload().getStatus() != null) {
            DSSDocument statusListToken = generateStatusListToken(attestation);
            return new ExternalResourcesAttestationRevocationSource(DSSUtils.toByteArray(statusListToken)).getAttestationRevocation(attestation);
        }
        return null;
    }

    /**
     * Compresses the input bytes
     *
     * @param input bytes to compress
     * @return compressed byte array
     */
    protected byte[] compressZlib(byte[] input) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
            dos.write(input);
            dos.finish();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new DSSException("Unable to compress", e);
        }
    }

}
