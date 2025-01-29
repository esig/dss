package eu.europa.esig.dss.cms.object;

import eu.europa.esig.dss.cms.AbstractCMSGenerator;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;

import java.util.Objects;

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

            CMSTypedData contentToBeSigned = getContentToBeSigned(toBeSignedDocument);

            CMSSignedData cmsSignedData = generator.generate(contentToBeSigned, encapsulate);
            return CMSUtils.populateDigestAlgorithmSet(new CMSSignedDataObject(cmsSignedData), digestAlgorithmIDs);

        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to build a CMSSignedData. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns the content to be signed
     *
     * @param toSignData {@link DSSDocument} to sign
     * @return {@link CMSTypedData}
     */
    protected CMSTypedData getContentToBeSigned(final DSSDocument toSignData) {
        Objects.requireNonNull(toSignData, "Document to be signed is missing");
        CMSTypedData content;
        if (toSignData instanceof DigestDocument) {
            content = new CMSAbsentContent();
        } else if (toSignData instanceof FileDocument) {
            FileDocument fileDocument = (FileDocument) toSignData;
            content = new CMSProcessableFile(fileDocument.getFile());
        } else {
            content = new CMSProcessableByteArray(DSSUtils.toByteArray(toSignData));
        }
        return content;
    }

}
