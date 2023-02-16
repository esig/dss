package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This check verifies if the certificate has a valid policy tree according to its certification path in regards to RFC 5280
 *
 */
public class PolicyTreeCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public PolicyTreeCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                           LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        final List<CertificateWrapper> certificateChain = new ArrayList<>();
        certificateChain.add(certificate);
        certificateChain.addAll(certificate.getCertificateChain()); // current certificate is not returned
        /*
         * (d)  explicit_policy:  an integer that indicates if a non-NULL
         * valid_policy_tree is required.
         * ...
         * If initial-explicit-policy is set, then the
         * initial value is 0, otherwise the initial value is n+1.
         */
        int explicitPolicy = certificateChain.size() + 1;
        PolicyTreeNode validPolicyTree = PolicyTreeNode.initTree();
        Set<PolicyTreeNode> previousLevelNodes = Collections.singleton(validPolicyTree);
        for (int i = certificateChain.size() - 1; i > -1; i--) {
            /*
             * (h) If certificate i is not self-issued:
             * (1) If explicit_policy is not 0, decrement explicit_policy by 1.
             * ...
             */
            final CertificateWrapper cert = certificateChain.get(i);
            if (explicitPolicy != 0 && !cert.isSelfSigned()) {
                --explicitPolicy;
            }
            /*
             * (i) (1) If requireExplicitPolicy is present and is less than
             * explicit_policy, set explicit_policy to the value of
             * requireExplicitPolicy.
             */
            int requireExplicitPolicy = cert.getRequireExplicitPolicy();
            if (requireExplicitPolicy != -1 && requireExplicitPolicy < explicitPolicy) {
                explicitPolicy = requireExplicitPolicy;
            }
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
                    // TODO : add inhibit_anyPolicy support
                    else if (i != 0 && cert.isSelfSigned()) {
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
            previousLevelNodes = currentLevelNodes;
            /*
             * (f) Verify that either explicit_policy is greater than 0 or the
             * valid_policy_tree is not equal to NULL;
             */
            if (explicitPolicy == 0 && validPolicyTree == null) {
                return false;
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