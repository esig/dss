package eu.europa.esig.dss.cms.object;

import eu.europa.esig.dss.cms.AbstractCMSGenerator;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * CMSGenerator implementation based on BouncyCastle {@code org.bouncycastle.cms.CMSSignedData}
 *
 */
public class CMSObjectGenerator extends AbstractCMSGenerator {

    /**
     * Default constructor
     */
    public CMSObjectGenerator() {
        super();
    }

    @Override
    public CMS generate() {
        try {
            final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            generator.addSignerInfoGenerator(signerInfoGenerator);
            generator.addCertificates(certificateStore);

            if (signers != null) {
                generator.addSigners(signers);
            }
            if (attributeCertificates != null) {
                generator.addAttributeCertificates(attributeCertificates);
            }
            if (crls != null) {
                generator.addCRLs(crls);
            }
            if (ocspBasicStore != null) {
                generator.addOtherRevocationInfo(id_pkix_ocsp_basic, ocspBasicStore);
            }
            if (ocspResponsesStore != null) {
                generator.addOtherRevocationInfo(id_ri_ocsp_response, ocspResponsesStore);
            }

            CMSTypedData contentToBeSigned = CMSUtils.toCMSEncapsulatedContent(toBeSignedDocument);

            CMSSignedData cmsSignedData = generator.generate(contentToBeSigned, encapsulate);
            return CMSUtils.populateDigestAlgorithmSet(new CMSSignedDataObject(cmsSignedData), digestAlgorithmIDs);

        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to build a CMSSignedData. Reason : %s", e.getMessage()), e);
        }
    }

}
