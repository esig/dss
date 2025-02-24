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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.tsl.AbstractTrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.tsl.TrustedListV5SignatureParametersBuilder;
import eu.europa.esig.dss.xades.tsl.TrustedListV6SignatureParametersBuilder;
import eu.europa.esig.dss.xades.tsl.XAdESTrustedListUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Implementation of a Trusted List signing service
 *
 */
public class RemoteTrustedListSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
        implements RemoteTrustedListSignatureService {

    private static final long serialVersionUID = 1029264702356172700L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteTrustedListSignatureServiceImpl.class);

    /** XAdES signature service */
    private XAdESService xadesService;

    /**
     * Default constructor instantiating object with null XAdESService
     */
    public RemoteTrustedListSignatureServiceImpl() {
        // empty
    }

    /**
     * Sets the XAdES signature service
     *
     * @param xadesService {@link XAdESService}
     */
    public void setXadesService(XAdESService xadesService) {
        this.xadesService = xadesService;
    }

    @Override
    public ToBeSignedDTO getDataToSign(final RemoteDocument trustedList,
                                       final RemoteTrustedListSignatureParameters parameters) throws DSSException {
        Objects.requireNonNull(xadesService, "XAdESService must be defined!");
        Objects.requireNonNull(trustedList, "Trusted List must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        Objects.requireNonNull(parameters.getSigningCertificate(), "Signing Certificate must be defined!");
        LOG.info("GetDataToSign in process...");

        DSSDocument tlDocument = RemoteDocumentConverter.toDSSDocument(trustedList);
        XAdESSignatureParameters signatureParameters = createParameters(tlDocument, parameters);
        ToBeSigned dataToSign = xadesService.getDataToSign(tlDocument, signatureParameters);

        LOG.info("GetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    @Override
    public RemoteDocument signDocument(final RemoteDocument trustedList,
                                       final RemoteTrustedListSignatureParameters parameters,
                                       final SignatureValueDTO signatureValue) throws DSSException {
        Objects.requireNonNull(xadesService, "XAdESService must be defined!");
        Objects.requireNonNull(trustedList, "Trusted List must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        Objects.requireNonNull(parameters.getSigningCertificate(), "Signing Certificate must be defined!");
        Objects.requireNonNull(signatureValue, "Signature Value must be defined!");
        LOG.info("SignDocument in process...");

        DSSDocument tlDocument = RemoteDocumentConverter.toDSSDocument(trustedList);
        XAdESSignatureParameters signatureParameters = createParameters(tlDocument, parameters);
        DSSDocument signDocument = xadesService.signDocument(tlDocument, signatureParameters, toSignatureValue(signatureValue));

        LOG.info("SignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signDocument);
    }

    private XAdESSignatureParameters createParameters(DSSDocument tlDocument, RemoteTrustedListSignatureParameters parameters) {
        CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(parameters.getSigningCertificate());
        AbstractTrustedListSignatureParametersBuilder tlParametersBuilder;
        if (parameters.getTlVersion() == null) {
            LOG.warn("Please provide a signatureParameters.tlVersion parameter! The XML Trusted List V5 is set by default.");
            tlParametersBuilder = new TrustedListV5SignatureParametersBuilder(certificateToken, tlDocument);
        } else if (!isValidTlVersion(parameters.getTlVersion())) {
            throw new DSSRemoteServiceException(String.format("The TlVersion parameter shall be represented " +
                    "by a valid integer! Obtained value '%s'.", parameters.getTlVersion()));
        } else {
            final Integer tlVersion = Integer.valueOf(parameters.getTlVersion());
            if (XAdESTrustedListUtils.TL_V5_IDENTIFIER.equals(tlVersion)) {
                tlParametersBuilder = new TrustedListV5SignatureParametersBuilder(certificateToken, tlDocument);
            } else if (XAdESTrustedListUtils.TL_V6_IDENTIFIER.equals(tlVersion)) {
                tlParametersBuilder = new TrustedListV6SignatureParametersBuilder(certificateToken, tlDocument);
            } else {
                throw new DSSRemoteServiceException(String.format("Unsupported TLVersionIdentifier '%s'!", parameters.getTlVersion()));
            }
        }

        tlParametersBuilder.assertConfigurationIsValid();

        if (parameters.getEncryptionAlgorithm() != null) {
            tlParametersBuilder.setEncryptionAlgorithm(parameters.getEncryptionAlgorithm());
        }
        if (parameters.getDigestAlgorithm() != null) {
            tlParametersBuilder.setDigestAlgorithm(parameters.getDigestAlgorithm());
        }
        if (parameters.getMaskGenerationFunction() != null) {
            tlParametersBuilder.setMaskGenerationFunction(parameters.getMaskGenerationFunction());
        }
        if (parameters.getBLevelParameters() != null) {
            tlParametersBuilder.setBLevelParams(toBLevelParameters(parameters.getBLevelParameters()));
        }
        if (parameters.getReferenceId() != null) {
            tlParametersBuilder.setReferenceId(parameters.getReferenceId());
        }
        if (parameters.getReferenceDigestAlgorithm() != null) {
            tlParametersBuilder.setReferenceDigestAlgorithm(parameters.getReferenceDigestAlgorithm());
        }

        return tlParametersBuilder.build();
    }

    private boolean isValidTlVersion(String tlVersion) {
        if (Utils.isStringDigits(tlVersion)) {
            try {
                return Integer.valueOf(tlVersion) != null;
            } catch (NumberFormatException e) {
                // silence
            }
        }
        return false;
    }

}
