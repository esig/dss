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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.validation.executor.AbstractTestValidationExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;

import java.io.File;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class AbstractProcessExecutorTest extends AbstractTestValidationExecutor {

    protected static I18nProvider i18nProvider;

    @BeforeAll
    static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    protected void validateBestSigningTimes(Reports reports) {
        DetailedReport detailedReport = reports.getDetailedReport();
        List<XmlSignature> xmlSignatures = detailedReport.getSignatures();
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature : xmlSignatures) {
            assertNotNull(xmlSignature.getValidationProcessBasicSignature().getProofOfExistence());
            assertNotNull(xmlSignature.getValidationProcessLongTermData().getProofOfExistence());
            assertNotNull(xmlSignature.getValidationProcessArchivalData().getProofOfExistence());
        }
    }

    protected ValidationPolicy loadTLPolicy() throws Exception {
        return ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy();
    }

    protected ValidationPolicy loadPolicyNoRevoc() throws Exception {
        return ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/test/resources/diag-data/policy/constraint-no-revoc.xml"));
    }

    protected ValidationPolicy loadPolicyRevocSha1OK() throws Exception {
        return ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/test/resources/diag-data/policy/revocation-sha1-ok-policy.xml"));
    }

    protected ValidationPolicy loadPolicyCryptoWarn() throws Exception {
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        CryptographicConstraint cryptographicConstraint = defaultPolicy.getDefaultCryptographicConstraint();
        cryptographicConstraint.setLevel(Level.WARN);
        cryptographicConstraint.getAlgoExpirationDate().setLevel(Level.WARN);
        return defaultPolicy;
    }

}
