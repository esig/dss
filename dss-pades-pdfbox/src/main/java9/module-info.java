module jpms_dss_pades_pdfbox {
    requires jpms_dss_pades;
   
    exports eu.europa.esig.dss.pdf.pdfbox;
    exports eu.europa.esig.dss.pdf.pdfbox.visible;
    exports eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;
    exports eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;
    
    provides eu.europa.esig.dss.pdf.IPdfObjFactory with eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
}