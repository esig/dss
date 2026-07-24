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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAADocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPresentationInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlError;
import eu.europa.esig.dss.diagnostic.jaxb.XmlErrors;
import eu.europa.esig.dss.eaa.common.validation.AttestationDocumentDiagnosticDataBuilder;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDeviceResponse;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDocument;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDocumentError;
import eu.europa.esig.dss.eaa.mdoc.model.MdocErrorItems;
import eu.europa.esig.dss.spi.eaa.Attestation;
import eu.europa.esig.dss.spi.eaa.AttestationPresentation;
import eu.europa.esig.dss.utils.Utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Builds a diagnostic data for the mdoc EAA presentation
 *
 */
public class MdocPresentationDiagnosticDataBuilder extends AttestationDocumentDiagnosticDataBuilder {

    /**
     * Default constructor
     */
    public MdocPresentationDiagnosticDataBuilder() {
        // empty
    }

    @Override
    protected XmlEAAPresentationInfo buildXmlEAAPresentationInfo(AttestationPresentation attestationPresentation) {
        final XmlEAAPresentationInfo xmlEAAPresentationInfo = super.buildXmlEAAPresentationInfo(attestationPresentation);
        if (attestationPresentation instanceof MdocAttestationPresentation) {
            MdocAttestationPresentation mdocEAAPresentation = (MdocAttestationPresentation) attestationPresentation;
            MdocDeviceResponse mdocDeviceResponse = mdocEAAPresentation.getMdocDeviceResponse();
            if (mdocDeviceResponse != null) {
                xmlEAAPresentationInfo.setVersion(mdocDeviceResponse.getVersion());
                xmlEAAPresentationInfo.setErrors(getXmlErrors(mdocDeviceResponse.getDocumentErrors()));
                xmlEAAPresentationInfo.setStatus(BigInteger.valueOf(mdocDeviceResponse.getStatus()));
            }
            return xmlEAAPresentationInfo;

        } else {
            throw new IllegalStateException("An instance of MdocEAAPresentation is expected!");
        }
    }

    private XmlErrors getXmlErrors(List<MdocDocumentError> documentErrors) {
        if (Utils.isCollectionNotEmpty(documentErrors)) {
            XmlErrors xmlErrors = new XmlErrors();
            for (MdocDocumentError documentError : documentErrors) {
                XmlError xmlError = new XmlError();
                xmlError.setLabel(documentError.getDocType());
                xmlError.setCode(BigInteger.valueOf(documentError.getErrorCode()));
                xmlErrors.getError().add(xmlError);
            }
        }
        return null;
    }

    @Override
    protected XmlEAADocument buildXmlEAADocument(Attestation attestation) {
        final XmlEAADocument xmlEAADocument = super.buildXmlEAADocument(attestation);
        if (attestation instanceof MdocAttestation) {
            MdocAttestation mdocEAA = (MdocAttestation) attestation;
            MdocDocument document = mdocEAA.getDocument();
            if (document != null) {
                xmlEAADocument.setDocumentType(document.getDocType());
                if (Utils.isMapNotEmpty(document.getErrors())) {
                    xmlEAADocument.getErrors().addAll(getXmlErrors(document.getErrors()));
                }
            }
            return xmlEAADocument;

        } else {
            throw new IllegalStateException("An instance of MdocEAA is expected!");
        }
    }

    private List<XmlErrors> getXmlErrors(Map<String, MdocErrorItems> errorItemsMap) {
        if (Utils.isMapNotEmpty(errorItemsMap)) {
            List<XmlErrors> xmlErrorsList = new ArrayList<>();
            for (Map.Entry<String, MdocErrorItems> entry : errorItemsMap.entrySet()) {
                XmlErrors xmlErrors = new XmlErrors();
                xmlErrors.setNamespace(entry.getKey());

                MdocErrorItems errorItems = entry.getValue();
                if (errorItems != null && Utils.isMapNotEmpty(errorItems.getErrorsMap())) {
                    for (Map.Entry<String, Long> errorEntry : errorItems.getErrorsMap().entrySet()) {
                        XmlError xmlError = new XmlError();
                        xmlError.setLabel(errorEntry.getKey());
                        xmlError.setCode(BigInteger.valueOf(errorEntry.getValue()));
                        xmlErrors.getError().add(xmlError);
                    }
                }
                xmlErrorsList.add(xmlErrors);
            }
            return xmlErrorsList;
        }
        return Collections.emptyList();
    }

    @Override
    protected XmlEAA buildDetachedXmlEAA(Attestation attestation) {
        XmlEAA xmlEAA = super.buildDetachedXmlEAA(attestation);
        MdocAttestation mdocEAA = (MdocAttestation) attestation;
        if (mdocEAA.getDocument() != null) {
            xmlEAA.setDocumentType(mdocEAA.getDocument().getDocType());
        }
        return xmlEAA;
    }

}
