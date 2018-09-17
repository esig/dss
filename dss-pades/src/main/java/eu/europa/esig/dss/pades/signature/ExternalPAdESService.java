package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * This service is stateful !
 * 
 *
 * @author david.naramski
 */
public class ExternalPAdESService extends PAdESService {

    byte[] rememberDigest;

    byte[] cmsSignedData;
    
    public ExternalPAdESService() {
        super(new DummyCertificateVerifier());
    }
    
    @Override
    protected byte[] computeDocumentDigest(DSSDocument toSignDocument, PAdESSignatureParameters parameters, PDFSignatureService pdfSignatureService) {
        byte[] digest = super.computeDocumentDigest(toSignDocument, parameters, pdfSignatureService);
        this.rememberDigest = digest;
        return digest;
    }
    
    @Override
    protected byte[] generateCMSSignedData(DSSDocument toSignDocument, PAdESSignatureParameters parameters, SignatureValue signatureValue,
            PDFSignatureService pdfSignatureService) {
        if(cmsSignedData == null) {
            throw new NullPointerException("A CMS signed data must be provided");
        }
        return cmsSignedData;
    }

    public void setCmsSignedData(byte[] cmsSignedData) {
        this.cmsSignedData = cmsSignedData;
    }
    
    public byte[] getDocumentDigest() {
        return rememberDigest;
    }

    static class DummyCertificateVerifier implements CertificateVerifier {

        @Override
        public OCSPSource getOcspSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public CRLSource getCrlSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setCrlSource(CRLSource crlSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void setOcspSource(OCSPSource ocspSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public CertificateSource getTrustedCertSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setTrustedCertSource(CertificateSource certSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public CertificateSource getAdjunctCertSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setAdjunctCertSource(CertificateSource adjunctCertSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public DataLoader getDataLoader() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setDataLoader(DataLoader dataLoader) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public ListCRLSource getSignatureCRLSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setSignatureCRLSource(ListCRLSource signatureCRLSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public ListOCSPSource getSignatureOCSPSource() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void setSignatureOCSPSource(ListOCSPSource signatureOCSPSource) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public CertificatePool createValidationPool() {
            // TODO Auto-generated method stub
            return null;
        }
        
    }
}
