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
package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationBasicValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.vpfbs.AbstractBasicValidationProcess;

import java.util.Map;

/**
 * Performs basic validation of a revocation data
 */
public class RevocationBasicValidationProcess extends AbstractBasicValidationProcess<XmlRevocationBasicValidation> {

    /**
     * Revocation data to be validated
     */
    private final RevocationWrapper revocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param revocationData {@link RevocationWrapper}
     * @param bbbs           map of BasicBuildingBlocks
     */
    public RevocationBasicValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                            RevocationWrapper revocationData, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlRevocationBasicValidation(), diagnosticData, revocationData, bbbs);
        this.revocationData = revocationData;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFRVC;
    }

    @Override
    protected void addAdditionalInfo() {
        result.setId(revocationData.getId());
    }

}
