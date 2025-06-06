package eu.europa.esig.dss.cms.stream.bc;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Extension of {@code CMSSignedDataStreamGenerator} in order to provide a custom digest algorithms set.
 * NOTE: This class contains a number of copy-pasted methods from CMSSignedDataStreamGenerator.
 * An issue {@code <a href="https://github.com/bcgit/bc-java/issues/1982">https://github.com/bcgit/bc-java/issues/1982</a>}
 * has been created in order to provide digestAlgorithms to original {@code CMSSignedDataStreamGenerator}.
 *
 */
public class DSSCMSSignedDataStreamGenerator extends CMSSignedDataStreamGenerator {

    /**
     * Additional digest algorithms IDs
     */
    private Set<AlgorithmIdentifier> digestAlgorithmIDs;

    /**
     * Default constructor
     */
    public DSSCMSSignedDataStreamGenerator() {
        // empty
    }

    /**
     * Sets additional digest algorithm IDs
     *
     * @param digestAlgorithmIDs a set of {@link AlgorithmIdentifier}s
     */
    public void addDigestAlgorithmIDs(Set<AlgorithmIdentifier> digestAlgorithmIDs) {
        this.digestAlgorithmIDs = digestAlgorithmIDs;
    }

    // NOTE: we have to override the method in order to add a custom embedding of digest algorithms
    @Override
    public OutputStream open(ASN1ObjectIdentifier eContentType, OutputStream out, boolean encapsulate, OutputStream dataOutputStream) throws IOException {

        //
        // ContentInfo
        //
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        //
        // Signed Data
        //
        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        sigGen.addObject(calculateVersion(eContentType));

        Set<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();

        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();

            addDigestAlgs(digestAlgs, signer);
        }

        //
        // add the new digests
        //

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();

            digestAlgs.add(signerGen.getDigestAlgorithm());
        }

        // add additional digest algorithms
        if (digestAlgorithmIDs != null && !digestAlgorithmIDs.isEmpty()) {
            digestAlgs.addAll(digestAlgorithmIDs);
        }

        sigGen.getRawOutputStream().write(convertToDlSet(digestAlgs).getEncoded());

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
        eiGen.addObject(eContentType);

        // If encapsulating, add the data as an octet string in the sequence
        OutputStream encapStream = encapsulate
                ? createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, true)
                : null;

        // Also send the data to 'dataOutputStream' if necessary
        OutputStream contentStream = getSafeTeeOutputStream(dataOutputStream, encapStream);

        // Let all the signers see the data as it is written
        OutputStream sigStream = attachSignersToOutputStream(signerGens, contentStream);

        return new DSSCmsSignedDataOutputStream(sigStream, eContentType, sGen, sigGen, eiGen);
    }

    private ASN1Integer calculateVersion(
            ASN1ObjectIdentifier contentOid)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (certs != null)
        {
            for (Iterator it = certs.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return new ASN1Integer(5);
        }

        if (crls != null)         // no need to check if otherCert is true
        {
            for (Iterator it = crls.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return new ASN1Integer(5);
        }

        if (attrCertV2Found)
        {
            return new ASN1Integer(4);
        }

        if (attrCertV1Found)
        {
            return new ASN1Integer(3);
        }

        if (checkForVersion3(_signers, signerGens))
        {
            return new ASN1Integer(3);
        }

        if (!CMSObjectIdentifiers.data.equals(contentOid))
        {
            return new ASN1Integer(3);
        }

        return new ASN1Integer(1);
    }

    private boolean checkForVersion3(List signerInfos, List signerInfoGens)
    {
        for (Iterator it = signerInfos.iterator(); it.hasNext();)
        {
            SignerInfo s = SignerInfo.getInstance(((SignerInformation)it.next()).toASN1Structure());

            if (s.getVersion().intValueExact() == 3)
            {
                return true;
            }
        }

        for (Iterator it = signerInfoGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator s = (SignerInfoGenerator)it.next();

            if (s.getGeneratedVersion() == 3)
            {
                return true;
            }
        }

        return false;
    }

    private static void addDigestAlgs(Set<AlgorithmIdentifier> digestAlgs, SignerInformation signer)
    {
        digestAlgs.add(signer.getDigestAlgorithmID());
        SignerInformationStore counterSignaturesStore = signer.getCounterSignatures();
        Iterator<SignerInformation> counterSignatureIt = counterSignaturesStore.iterator();
        while (counterSignatureIt.hasNext())
        {
            SignerInformation counterSigner = counterSignatureIt.next();
            digestAlgs.add(counterSigner.getDigestAlgorithmID());
        }
    }

    private static ASN1Set convertToDlSet(Set<AlgorithmIdentifier> digestAlgs)
    {
        return new DLSet(digestAlgs.toArray(new AlgorithmIdentifier[0]));
    }

    private static OutputStream createBEROctetOutputStream(OutputStream s, int tagNo, boolean isExplicit)
            throws IOException
    {
        BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);
        return octGen.getOctetOutputStream();
    }

    private static OutputStream getSafeOutputStream(OutputStream s)
    {
        return s == null ? Utils.nullOutputStream() : s;
    }

    private static OutputStream getSafeTeeOutputStream(OutputStream s1, OutputStream s2)
    {
        return s1 == null ? getSafeOutputStream(s2)
                : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
                s1, s2);
    }

    private static OutputStream attachSignersToOutputStream(Collection signers, OutputStream s)
    {
        OutputStream result = s;
        Iterator it = signers.iterator();
        while (it.hasNext())
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
        }
        return result;
    }

    @Override
    public List<AlgorithmIdentifier> getDigestAlgorithms() {
        List<AlgorithmIdentifier> digestAlgorithms = super.getDigestAlgorithms();
        digestAlgorithms.addAll(digestAlgorithmIDs);
        return digestAlgorithms;
    }

    private class DSSCmsSignedDataOutputStream
            extends OutputStream
    {
        private OutputStream         _out;
        private ASN1ObjectIdentifier _contentOID;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;
        private BERSequenceGenerator _eiGen;

        public DSSCmsSignedDataOutputStream(
                OutputStream         out,
                ASN1ObjectIdentifier contentOID,
                BERSequenceGenerator sGen,
                BERSequenceGenerator sigGen,
                BERSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = contentOID;
            _sGen = sGen;
            _sigGen = sigGen;
            _eiGen = eiGen;
        }

        public void write(
                int b)
                throws IOException
        {
            _out.write(b);
        }

        public void write(
                byte[] bytes,
                int    off,
                int    len)
                throws IOException
        {
            _out.write(bytes, off, len);
        }

        public void write(
                byte[] bytes)
                throws IOException
        {
            _out.write(bytes);
        }

        public void close()
                throws IOException
        {
            _out.close();
            _eiGen.close();

            digests.clear();    // clear the current preserved digest state

            if (certs.size() != 0)
            {
                ASN1Set certSet = createBerSetFromList(certs);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, certSet).getEncoded());
            }

            if (crls.size() != 0)
            {
                ASN1Set crlSet = createBerSetFromList(crls);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, crlSet).getEncoded());
            }

            //
            // collect all the SignerInfo objects
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();

            //
            // add the precalculated SignerInfo objects
            //
            {
                Iterator it = _signers.iterator();
                while (it.hasNext())
                {
                    SignerInformation signer = (SignerInformation)it.next();
                    signerInfos.add(signer.toASN1Structure());
                }
            }

            //
            // add the generated SignerInfo objects
            //

            for (Iterator it = signerGens.iterator(); it.hasNext();)
            {
                SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();

                try
                {
                    signerInfos.add(sigGen.generate(_contentOID));

                    byte[] calculatedDigest = sigGen.getCalculatedDigest();

                    digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
                }
                catch (CMSException e)
                {
                    throw new DSSException("Exception generating signers: " + e.getMessage(), e);
                }
            }

            _sigGen.getRawOutputStream().write(new DLSet(signerInfos).getEncoded());

            _sigGen.close();
            _sGen.close();
        }

        private ASN1Set createBerSetFromList(List derObjects)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            for (Iterator it = derObjects.iterator(); it.hasNext(); )
            {
                v.add((ASN1Encodable)it.next());
            }

            return new BERSet(v);
        }

    }

}
