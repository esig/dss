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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Creates Signature parameters for a Trusted List V5 creation
 * <p>
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 */
public class TrustedListV5SignatureParametersBuilder extends AbstractTrustedListSignatureParametersBuilder {

    /**
     * The constructor to build Signature Parameters for a Trusted List V5 signing with respect to ETSI TS 119 612
     *
     * @param signingCertificate {@link CertificateToken} to be used for a signature creation
     * @param tlXmlDocument      {@link DSSDocument} Trusted List XML document to be signed
     */
    public TrustedListV5SignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
        super(signingCertificate, tlXmlDocument);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setReferenceId(String referenceId) {
        return (TrustedListV5SignatureParametersBuilder) super.setReferenceId(referenceId);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setReferenceDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setDigestAlgorithm(digestAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        return (TrustedListV5SignatureParametersBuilder) super.setEncryptionAlgorithm(encryptionAlgorithm);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        return (TrustedListV5SignatureParametersBuilder) super.setMaskGenerationFunction(maskGenerationFunction);
    }

    @Override
    public TrustedListV5SignatureParametersBuilder setBLevelParams(BLevelParameters bLevelParams) {
        return (TrustedListV5SignatureParametersBuilder) super.setBLevelParams(bLevelParams);
    }

    @Override
    protected boolean isEn319132() {
        return false;
    }

    @Override
    protected Integer getTargetTLVersion() {
        return 5;
    }

}
