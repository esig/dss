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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * WebService for CMS signature creation compatible for PAdES signature creation 
 * (enveloping within /Contents of a PDF signature revision).
 *
 */
public class RemoteExternalCMSServiceImpl extends AbstractRemoteSignatureServiceImpl implements RemoteExternalCMSService {

    private static final long serialVersionUID = -8128859790984520949L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteExternalCMSServiceImpl.class);

    /** Service to generate a CMS compliant for a PAdES signature creation */
    private ExternalCMSService service;

    /**
     * Default constructor instantiating object with null RemoteExternalCMSServiceImpl
     */
    public RemoteExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the {@code ExternalCMSService}
     *
     * @param service {@link ExternalCMSService}
     */
    public void setService(ExternalCMSService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(final DigestDTO messageDigestDTO, final RemoteSignatureParameters parameters) {
        Objects.requireNonNull(service, "PAdESExternalCMSSignatureService must be defined!");
        Objects.requireNonNull(messageDigestDTO, "MessageDigest must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        assertPAdESParameters(parameters);
        LOG.info("GetDataToSign in process...");

        DSSMessageDigest messageDigest = toMessageDigest(messageDigestDTO);
        PAdESSignatureParameters padesParameters = (PAdESSignatureParameters) createParameters(parameters);
        ToBeSigned dataToSign = service.getDataToSign(messageDigest, padesParameters);

        LOG.info("GetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    @Override
    public RemoteDocument signMessageDigest(final DigestDTO messageDigestDTO, final RemoteSignatureParameters parameters,
                                            SignatureValueDTO signatureValueDTO) {
        Objects.requireNonNull(service, "PAdESExternalCMSSignatureService must be defined!");
        Objects.requireNonNull(messageDigestDTO, "MessageDigest must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "SignatureValue must be defined!");
        assertPAdESParameters(parameters);
        LOG.info("SignMessageDigest in process...");

        DSSMessageDigest messageDigest = toMessageDigest(messageDigestDTO);
        PAdESSignatureParameters padesParameters = (PAdESSignatureParameters) createParameters(parameters);
        SignatureValue signatureValue = DTOConverter.toSignatureValue(signatureValueDTO);
        CMSSignedDocument cmsSignature = service.signMessageDigest(messageDigest, padesParameters, signatureValue);

        LOG.info("SignMessageDigest is finished");
        return RemoteDocumentConverter.toRemoteDocument(cmsSignature);
    }

    private DSSMessageDigest toMessageDigest(DigestDTO digest) {
        if (digest != null) {
            return new DSSMessageDigest(digest.getAlgorithm(), digest.getValue());
        }
        return null;
    }

    private void assertPAdESParameters(RemoteSignatureParameters parameters) {
        Objects.requireNonNull(parameters.getSignatureLevel(), "signatureLevel must be defined!");
        if (!SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {
            throw new UnsupportedOperationException("PAdES signature form is required! " +
                    "Please update SignatureLevel within parameters.");
        }
    }
    
}
