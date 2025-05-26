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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_LT;
import static eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_T;

/**
 * This class is used to extend an ASiC with CAdES signature
 *
 */
public class ASiCWithCAdESSignatureExtension implements Serializable {

    private static final long serialVersionUID = 4054926235641779454L;

    /** The CertificateVerifier used for a certificate chain validation */
    protected final CertificateVerifier certificateVerifier;

    /** The TSPSource to use for timestamp requests */
    protected final TSPSource tspSource;

    /** The CAdESService to be used for a CAdES signature extension */
    private CAdESService cadesService;

    /** This object is used to create data container objects such as an OutputStream or a DSSDocument */
    protected DSSResourcesHandlerBuilder resourcesHandlerBuilder;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param tspSource {@link TSPSource}
     */
    public ASiCWithCAdESSignatureExtension(final CertificateVerifier certificateVerifier, final TSPSource tspSource) {
        this.certificateVerifier = certificateVerifier;
        this.tspSource = tspSource;
    }

    /**
     * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
     * during the signature creation procedure.
     *
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     */
    public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = resourcesHandlerBuilder;
    }

    /**
     * This method is used to extend signatures within the {@code ASiCContent}
     *
     * @param asicContent {@link ASiCContent}
     * @param parameters {@link CAdESSignatureParameters}
     * @return {@link ASiCContent} with extended signature documents
     */
    public ASiCContent extend(ASiCContent asicContent, CAdESSignatureParameters parameters) {
        List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();

        ASiCContainerType containerType = asicContent.getContainerType();
        if (containerType == null) {
            throw new IllegalInputException("The container type of the provided document is not supported or cannot be extracted!");
        }

        for (DSSDocument signature : signatureDocuments) {
            boolean coveredByManifest = isCoveredByManifest(asicContent, signature);
            if (extensionRequired(parameters, coveredByManifest)) {
                // not to extend the signature covered by a manifest
                assertExtendSignaturePossible(parameters, coveredByManifest);

                DSSDocument extendedSignature = extendSignatureDocument(signature, asicContent, parameters);
                ASiCUtils.addOrReplaceDocument(signatureDocuments, extendedSignature);
            }
        }

        return asicContent;
    }

    private DSSDocument extendSignatureDocument(DSSDocument signature, ASiCContent asicContent,
                                                CAdESSignatureParameters cadesParameters) {
        List<DSSDocument> detachedContents = getDetachedContents(signature, asicContent);
        cadesParameters.getContext().setDetachedContents(detachedContents);

        String originalName = signature.getName();
        DSSDocument extendDocument = getCAdESService().extendDocument(signature, cadesParameters);
        extendDocument.setName(originalName);
        return extendDocument;
    }

    private List<DSSDocument> getDetachedContents(DSSDocument signatureDocument, ASiCContent asicContent) {
        if (ASiCContainerType.ASiC_E == asicContent.getContainerType()) {
            List<DSSDocument> manifests = asicContent.getManifestDocuments();
            DSSDocument linkedManifest = ASiCManifestParser.getLinkedManifest(manifests, signatureDocument.getName());
            return Collections.singletonList(linkedManifest);

        } else {
            return asicContent.getSignedDocuments();
        }
    }

    /**
     * Returns params.referenceDigestAlgorithm if exists, params.digestAlgorithm otherwise
     *
     * @param params {@link CAdESSignatureParameters}
     * @return {@link DigestAlgorithm}
     */
    protected DigestAlgorithm getReferenceDigestAlgorithmOrDefault(CAdESSignatureParameters params) {
        return params.getReferenceDigestAlgorithm() != null ? params.getReferenceDigestAlgorithm() : params.getDigestAlgorithm();
    }

    private CAdESService getCAdESService() {
        if (cadesService == null) {
            cadesService = new CAdESService(certificateVerifier);
            cadesService.setTspSource(tspSource);
            if (CAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER != resourcesHandlerBuilder) {
                cadesService.setResourcesHandlerBuilder(resourcesHandlerBuilder);
            }
        }
        return cadesService;
    }

    /**
     * Checks whether the signature extension is required for the particular document
     *
     * @param parameters {@link CAdESSignatureParameters}
     * @param coveredByManifest defines whether the signature document is covered by an archive manifest
     * @return TRUE if the signature extension is required, FALSE otherwise
     */
    protected boolean extensionRequired(CAdESSignatureParameters parameters, boolean coveredByManifest) {
        SignatureLevel signatureLevel = parameters.getSignatureLevel();
        return CAdES_BASELINE_T.equals(signatureLevel) || CAdES_BASELINE_LT.equals(signatureLevel) || !coveredByManifest;
    }

    /**
     * Checks if the signature extension is possible
     *
     * @param parameters {@link CAdESSignatureParameters}
     * @param coveredByManifest defines whether the signature document is covered by an archive manifest
     */
    protected void assertExtendSignaturePossible(CAdESSignatureParameters parameters, boolean coveredByManifest) {
        SignatureLevel signatureLevel = parameters.getSignatureLevel();
        if ((CAdES_BASELINE_T.equals(signatureLevel) || CAdES_BASELINE_LT.equals(signatureLevel)) && coveredByManifest) {
            throw new IllegalInputException(String.format(
                    "Cannot extend signature to '%s'. The signature is already covered by an archive manifest.", signatureLevel));
        }
    }

    /**
     * Verifies whether the {@code signature} document is covered by an Archive Manifest
     *
     * @param asicContent {@link ASiCContent}
     * @param signature {@link DSSDocument}
     * @return TRUE if the signature is covered by an archive manifest, FALSE otherwise
     */
    protected boolean isCoveredByManifest(ASiCContent asicContent, DSSDocument signature) {
        return ASiCUtils.isCoveredByManifest(asicContent.getAllManifestDocuments(), signature.getName());
    }

}
