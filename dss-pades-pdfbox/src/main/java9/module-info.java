module jpms_dss_pades_pdfbox {
    requires jpms_dss_pades;
    provides eu.europa.esig.dss.pdf.IPdfObjFactory with eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
}