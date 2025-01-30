package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.AbstractCMSGenerator;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.util.ArrayList;
import java.util.List;

/**
 * Generates a {@code eu.europa.esig.dss.cms.stream.CMSSignedDataStream} implementation
 *
 */
public class CMSStreamGenerator extends AbstractCMSGenerator {

    /**
     * Default constructor
     */
    public CMSStreamGenerator() {
        super();
    }

    @Override
    public CMS generate() {
        final CMSSignedDataStream cms = new CMSSignedDataStream();

        cms.setSignerInfos(getSignerInfos(signerInfoGenerator, toBeSignedDocument));
        cms.setDigestAlgorithmIDs(digestAlgorithmIDs);

        cms.setSignedContent(toBeSignedDocument);
        cms.setDetachedSignature(!encapsulate);

        cms.setCertificates(certificateStore);
        cms.setAttributeCertificates(attributeCertificates);
        cms.setCRLs(crls);
        cms.setOcspResponseStore(ocspResponsesStore);
        cms.setOcspBasicStore(ocspBasicStore);

        return cms;
    }

    private SignerInformationStore getSignerInfos(SignerInfoGenerator signerInfoGenerator, DSSDocument toSignDocument) {
        final List<SignerInformation> signerInformationList = new ArrayList<>();
        if (signers != null) {
            signerInformationList.addAll(signers.getSigners());
        }

        try {
            // Generate new signer (simplified)
            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
            CMSTypedData contentToBeSigned = CMSUtils.toCMSEncapsulatedContent(toSignDocument);
            SignerInformationStore newSignerInfos = cmsSignedDataGenerator.generate(contentToBeSigned, false).getSignerInfos();
            signerInformationList.addAll(newSignerInfos.getSigners());

        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to generate a SignerInformation. Reason : %s", e.getMessage()), e);
        }

        return new SignerInformationStore(signerInformationList);
    }

}
