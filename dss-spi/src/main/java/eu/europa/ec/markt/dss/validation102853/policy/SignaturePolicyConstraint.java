/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_VCI_ISPK_ANS_1;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_VCI_ISPK_ANS_2;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_VCI_ISPK_ANS_3;

/**
 * This class represents a signature policy constraint. The validation is composed of:
 * - check of the .
 * - check of the .
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class SignaturePolicyConstraint extends Constraint {

    private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyConstraint.class);

    /**
     * This variable stores the used signature policy identifier. If no policy is used then it contains {@code NO_POLICY}, if the policy is implied then it contains {@code
     * IMPLICIT_POLICY}, if the policy is absent then it contains {@code ANY_POLICY}.
     */
    protected String identifier;

    /**
     * This variable stores the signature policy validity in case the policy identifier references a policy file.
     */
    protected Boolean policyValidity;

    /**
     * This variable stores the signature policy processing error in case where an error has been encountered when  processing the signature validation policy.
     */
    protected String processingError;

    /**
     * This variable stores the signature policy notice if any.
     */
    protected String notice;

    /**
     * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
     * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
     *
     * @param level the constraint level string.
     */
    public SignaturePolicyConstraint(final String level) {

        super(level);
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(final String policyId) {
        this.identifier = policyId;
    }

    public Boolean getPolicyValidity() {
        return policyValidity;
    }

    public void setPolicyValidity(final Boolean policyValidity) {
        this.policyValidity = policyValidity;
    }

    public String getProcessingError() {
        return processingError;
    }

    public void setProcessingError(final String processingError) {
        this.processingError = processingError;
    }

    public String getNotice() {
        return notice;
    }

    public void setNotice(final String notice) {
        this.notice = notice;
    }

    /**
     * This method carry out the validation of the constraint.
     *
     * @return true if the constraint is met, false otherwise.
     */
    @Override
    public boolean check() {

        if (ignore()) {

            node.addChild(STATUS, IGNORED);
            return true;
        }
        if (inform()) {

            node.addChild(STATUS, INFORMATION);
            node.addChild(INFO, null, messageAttributes).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
            return true;
        }
        if (!SignaturePolicy.IMPLICIT_POLICY.equals(identifier)) {

            if (SignaturePolicy.NO_POLICY.equals(identifier)) {

                if (!identifiers.contains(identifier)) {

                    if (warn()) {

                        node.addChild(STATUS, WARN);
                        node.addChild(WARNING, BBB_VCI_ISPK_ANS_1).setAttribute(EXPECTED_VALUE, expectedValue);
                        conclusion.addWarning(BBB_VCI_ISPK_ANS_1).setAttribute(EXPECTED_VALUE, expectedValue);
                        return true;
                    }
                    node.addChild(STATUS, KO);
                    node.addChild(ERROR, BBB_VCI_ISPK_ANS_1);
                    conclusion.setIndication(INDETERMINATE, NO_POLICY);
                    conclusion.addError(BBB_VCI_ISPK_ANS_1).setAttribute(EXPECTED_VALUE, expectedValue);
                    return false;
                }
            } else {

                if (!identifiers.contains(RuleConstant.ANY_POLICY)) {

                    if (!policyValidity) {

                        if (warn()) {

                            node.addChild(STATUS, WARN);
                            node.addChild(WARNING, BBB_VCI_ISPK_ANS_2).setAttribute(ERROR, processingError);
                            final Conclusion.Warning warning = conclusion.addWarning(BBB_VCI_ISPK_ANS_2);
                            warning.setAttribute(ERROR, processingError);
                            return true;
                        }
                        node.addChild(STATUS, KO);
                        node.addChild(ERROR, BBB_VCI_ISPK_ANS_2);
                        conclusion.setIndication(INDETERMINATE, POLICY_PROCESSING_ERROR);
                        final Conclusion.Error error = conclusion.addError(BBB_VCI_ISPK_ANS_2);
                        error.setAttribute(ERROR, processingError);
                        return false;
                    }
                    if (!identifiers.contains(identifier)) {

                        if (warn()) {

                            node.addChild(STATUS, WARN);
                            node.addChild(WARNING, BBB_VCI_ISPK_ANS_3).setAttribute(ERROR, processingError);
                            final Conclusion.Warning warning = conclusion.addWarning(BBB_VCI_ISPK_ANS_3);
                            warning.setAttribute(EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
                            return true;
                        }
                        node.addChild(STATUS, KO);
                        node.addChild(ERROR, BBB_VCI_ISPK_ANS_3);
                        conclusion.setIndication(INDETERMINATE, NO_POLICY);
                        final Conclusion.Error error = conclusion.addError(BBB_VCI_ISPK_ANS_3);
                        error.setAttribute(EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
                        return false;
                    }
                }
            }
        }
        node.addChild(STATUS, OK);
        final XmlNode info = node.addChild(INFO);
        info.setAttribute(IDENTIFIER, identifier);
        if (!notice.isEmpty()) {

            info.setAttribute(NOTICE, notice);
        }
        return true;
    }
}

