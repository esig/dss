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
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.attestation.checks.DisclosureListExhaustiveCheck;
import eu.europa.esig.dss.validation.process.attestation.checks.DisclosurePresentCheck;
import eu.europa.esig.dss.validation.process.attestation.checks.AttestationSignatureUnicityCheck;
import eu.europa.esig.dss.validation.process.attestation.checks.KeyBindingSignaturePresentCheck;

/**
 * Verifies format of an Electronic Attestation of Attributes (EAA)
 *
 */
public class AttestationFormatChecking extends AbstractFormatChecking<AttestationWrapper> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param eaa {@link AttestationWrapper}
     * @param context {@link Context}
     * @param policy {@link ValidationPolicy}
     */
    public AttestationFormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                     AttestationWrapper eaa, Context context, ValidationPolicy policy) {
        super(i18nProvider, diagnosticData, eaa, context, policy);
    }

    @Override
    protected void initChain() {

        ChainItem<XmlFC> item = firstItem = signatureUnicity();

        item = item.setNextItem(disclosurePresent());

        item = item.setNextItem(disclosureListExhaustive());

        item = item.setNextItem(keyBindingSignaturePresent());

    }

    private ChainItem<XmlFC> signatureUnicity() {
        LevelRule constraint = policy.getEAASignatureUnicityConstraint();
        return new AttestationSignatureUnicityCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlFC> disclosurePresent() {
        LevelRule constraint = policy.getEAADisclosurePresentConstraint();
        return new DisclosurePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlFC> disclosureListExhaustive() {
        LevelRule constraint = policy.getEAADisclosureListExhaustiveConstraint();
        return new DisclosureListExhaustiveCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlFC> keyBindingSignaturePresent() {
        LevelRule constraint = policy.getEAAKeyBindingSignaturePresentConstraint();
        return new KeyBindingSignaturePresentCheck(i18nProvider, result, token, constraint);
    }

}
