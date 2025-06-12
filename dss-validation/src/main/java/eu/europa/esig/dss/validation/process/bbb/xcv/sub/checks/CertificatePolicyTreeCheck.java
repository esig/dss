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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This check verifies if the certificate has a valid policy tree according to its certification path in regard to RFC 5280
 *
 */
public class CertificatePolicyTreeCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelRule}
     */
    public CertificatePolicyTreeCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                      LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        /*
         * 6.1.2. Initialization
         */
        final List<CertificateWrapper> certificateChain = new ArrayList<>();
        certificateChain.add(certificate);
        certificateChain.addAll(certificate.getCertificateChain()); // current certificate is not returned
        /*
         * (a) valid_policy_tree:  A tree of certificate policies with their
         * optional qualifiers; each of the leaves of the tree
         * represents a valid policy at this stage in the certification
         * path validation.
         * ...
         * The initial value of the valid_policy_tree is a single node with
         * valid_policy anyPolicy, an empty qualifier_set, and an
         * expected_policy_set with the single value anyPolicy.
         * This node is considered to be at depth zero.
         */
        PolicyTreeNode validPolicyTree = PolicyTreeNode.initTree();
        /*
         * (d) explicit_policy:  an integer that indicates if a non-NULL
         * valid_policy_tree is required.
         * ...
         * If initial-explicit-policy is set, then the
         * initial value is 0, otherwise the initial value is n+1.
         */
        int explicitPolicy = certificateChain.size() + 1;
        /*
         * (e) inhibit_anyPolicy:  an integer that indicates whether the
         * anyPolicy policy identifier is considered a match.
         * ...
         * If initial-any-policy-inhibit is set, then the initial value is 0,
         * otherwise the initial value is n+1.
         */
        int inhibitAnyPolicy = certificateChain.size() + 1;

        // internal variable to facilitate processing
        Set<PolicyTreeNode> previousLevelNodes = Collections.singleton(validPolicyTree);

        /*
         * 6.1.3. Basic Certificate Processing
         * The basic path processing actions to be performed for certificate i
         * (for all i in [1..n]) are listed below.
         */
        for (int i = certificateChain.size() - 1; i > -1; i--) {
            final CertificateWrapper cert = certificateChain.get(i);
            int certRequireExplicitPolicy = cert.getRequireExplicitPolicy();
            int certInhibitAnyPolicy = cert.getInhibitAnyPolicy();
            /*
             * (d) If the certificate policies extension is present in the
             * certificate and the valid_policy_tree is not NULL, process
             * the policy information by performing the following steps in
             * order:
             */
            Set<PolicyTreeNode> currentLevelNodes = new HashSet<>();
            List<XmlCertificatePolicy> certificatePolicies = cert.getCertificatePolicies();
            if (Utils.isCollectionNotEmpty(certificatePolicies) && Utils.isCollectionNotEmpty(previousLevelNodes)) {
                for (XmlCertificatePolicy certificatePolicy : certificatePolicies) {
                    PolicyTreeNode policyNode = new PolicyTreeNode(certificatePolicy.getValue(), certificatePolicy.getCpsUrl());
                    /*
                     * (1) For each policy P not equal to anyPolicy in the
                     * certificate policies extension, let P-OID denote the OID
                     * for policy P and P-Q denote the qualifier set for policy P.
                     * Perform the following steps in order:
                     */
                    if (!policyNode.isAnyPolicy()) {
                        for (PolicyTreeNode node : previousLevelNodes) {
                            if (node.addChildNodeIfMatch(policyNode)) {
                                currentLevelNodes.add(policyNode);
                            }
                        }
                    }
                    /*
                     * (2) If the certificate policies extension includes the policy
                     * anyPolicy with the qualifier set AP-Q and either (a)
                     * inhibit_anyPolicy is greater than 0 or (b) i<n and the
                     * certificate is self-issued, then:
                     */
                    else if (inhibitAnyPolicy > 0 || (i != 0 && cert.isSelfSigned())) {
                        for (PolicyTreeNode node : previousLevelNodes) {
                            Set<PolicyTreeNode> children = node.createAnyPolicyChildren();
                            currentLevelNodes.addAll(children);
                        }
                    }
                }
                /*
                 * (3) If there is a node in the valid_policy_tree of depth i-1
                 * or less without any child nodes, delete that node. Repeat
                 * this step until there are no nodes of depth i-1 or less
                 * without children.
                 */
                if (validPolicyTree != null) {
                    validPolicyTree = validPolicyTree.deleteNodesAtLevelWithoutChildren(certificateChain.size() - 1 - i);
                }
            }
            /*
             * (e) If the certificate policies extension is not present, set the
             * valid_policy_tree to NULL.
             */
            else if (Utils.isCollectionEmpty(certificatePolicies)) {
                validPolicyTree = null;
            }
            /*
             * (f) Verify that either explicit_policy is greater than 0 or the
             * valid_policy_tree is not equal to NULL;
             */
            // skip this step in order to support flexible validation policy
            /*
             * If i is not equal to n, continue by performing the preparatory steps
             * listed in Section 6.1.4. If i is equal to n, perform the wrap-up
             * steps listed in Section 6.1.5.
             */
            // descending order
            if (i != 0) {
                /*
                 * 6.1.4. Preparation for Certificate i+1
                 */
                previousLevelNodes = currentLevelNodes;
                /*
                 * (h) If certificate i is not self-issued:
                 */
                if (!cert.isSelfSigned()) {
                    /*
                     * (1) If explicit_policy is not 0, decrement explicit_policy by 1.
                     * ...
                     */
                    if (explicitPolicy != 0) {
                        --explicitPolicy;
                    }
                    /*
                     * (3) If inhibit_anyPolicy is not 0, decrement inhibit_anyPolicy by 1.
                     */
                    if (inhibitAnyPolicy != 0) {
                        --inhibitAnyPolicy;
                    }
                }
                /*
                 * (i) (1) If requireExplicitPolicy is present and is less than
                 * explicit_policy, set explicit_policy to the value of
                 * requireExplicitPolicy.
                 */
                if (certRequireExplicitPolicy != -1 && certRequireExplicitPolicy < explicitPolicy) {
                    explicitPolicy = certRequireExplicitPolicy;
                }
                /*
                 * (j) If the inhibitAnyPolicy extension is included in the
                 * certificate and is less than inhibit_anyPolicy, set
                 * inhibit_anyPolicy to the value of inhibitAnyPolicy.
                 */
                if (certInhibitAnyPolicy != -1 && certInhibitAnyPolicy < inhibitAnyPolicy) {
                    inhibitAnyPolicy = certInhibitAnyPolicy;
                }
            }
            /*
             * 6.1.5. Wrap-Up Procedure
             * To complete the processing of the target certificate, perform the
             * following steps for certificate n:
             */
            else {
                /*
                 * (a) If explicit_policy is not 0, decrement explicit_policy by 1.
                 */
                if (explicitPolicy != 0) {
                    --explicitPolicy;
                }
                /*
                 * (b) If a policy constraints extension is included in the
                 * certificate and requireExplicitPolicy is present and has a
                 * value of 0, set the explicit_policy state variable to 0.
                 */
                if (certRequireExplicitPolicy == 0) {
                    explicitPolicy = 0;
                }
                /*
                 * If either (1) the value of explicit_policy variable is greater than
                 * zero or (2) the valid_policy_tree is not NULL, then path processing
                 * has succeeded.
                 */
                if (explicitPolicy == 0 && validPolicyTree == null) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_ICPTV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_ICPTV_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
    }

}