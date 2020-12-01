package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.pades.validation.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PdfRevisionTimestampSource extends AbstractTimestampSource {

    public final PdfRevision pdfRevision;

    public PdfRevisionTimestampSource(final PdfRevision pdfRevision) {
        this.pdfRevision = pdfRevision;
    }

    public List<TimestampedReference> getIncorporatedReferences() {
        if (pdfRevision instanceof PdfDocTimestampRevision) {
            PdfDocTimestampRevision pdfDocTimestampRevision = (PdfDocTimestampRevision) pdfRevision;

            final TimestampToken timestampToken = pdfDocTimestampRevision.getTimestampToken();
            return getReferencesFromTimestamp(timestampToken);

        } else if (pdfRevision instanceof PdfDocDssRevision) {
            PdfDocDssRevision pdfDocDssRevision = (PdfDocDssRevision) pdfRevision;

            PdfDssDict dssDictionary = pdfDocDssRevision.getDssDictionary();
            final List<TimestampedReference> references = new ArrayList<>();

            CertificateSource certificateSource = new PdfDssDictCertificateSource(dssDictionary);
            addReferences(references, createReferencesForCertificates(certificateSource.getCertificates()));

            PdfDssDictCRLSource crlSource = new PdfDssDictCRLSource(dssDictionary);
            addReferences(references, createReferencesForIdentifiers(
                    crlSource.getDSSDictionaryBinaries(), TimestampedObjectType.REVOCATION));
            addReferences(references, createReferencesForIdentifiers(
                    crlSource.getVRIDictionaryBinaries(), TimestampedObjectType.REVOCATION));

            PdfDssDictOCSPSource ocspSource = new PdfDssDictOCSPSource(dssDictionary);
            addReferences(references, createReferencesForIdentifiers(
                    ocspSource.getDSSDictionaryBinaries(), TimestampedObjectType.REVOCATION));
            addReferences(references, createReferencesForIdentifiers(
                    ocspSource.getVRIDictionaryBinaries(), TimestampedObjectType.REVOCATION));

            return references;
        }

        return Collections.emptyList();
    }

}
