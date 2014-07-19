package eu.europa.ec.markt.dss;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public final class DSSPDFUtils {

    private DSSPDFUtils() {
    }

    public static byte[] getBytes(final PdfArray crlArray, final int ii) throws DSSException {

        try {

            return crlArray.getBytes(ii);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public static File getFileFromPdfData(final InputStream pdfData) throws DSSException {

        FileOutputStream fileOutputStream = null;
        try {

            // TODO: (Bob: 2014 Jan 22) There is no guarantee that there will be no duplicates
            final File file = File.createTempFile("raw", ".pdf");
            fileOutputStream = new FileOutputStream(file);
            DSSUtils.copy(pdfData, fileOutputStream);
            return file;
        } catch (IOException e) {
            throw new DSSException("The process has no rights to write or to access 'java.io.tmpdir': " + System.getProperty("java.io.tmpdir"), e);
        } finally {

            DSSUtils.closeQuietly(fileOutputStream);
        }
    }

    public static void close(PDDocument doc) throws DSSException {

        if (doc != null) {

            try {
                doc.close();
            } catch (IOException e) {
                throw new DSSException(e);
            }
        }
    }
}
